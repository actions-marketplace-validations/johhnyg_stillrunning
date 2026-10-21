"""v2.13.7 — import hook actually scans and acts on BLOCKED; wrappers only
block on a real verdict (docs/import-hook-audit.md H-1..H-4 + wrapper exit codes)."""
import io
import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from stillrunning import cli, hook, intercept


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def scan(monkeypatch):
    calls, flagged = [], []

    def run(response=None, http_error=None, token="tok", dist="evilpkg-dist"):
        calls.clear(); flagged.clear()
        hook._warned.clear()
        monkeypatch.setattr(hook, "_get_api_token", lambda: token)
        monkeypatch.setattr(hook, "_distribution_for", lambda name: dist)
        monkeypatch.setattr(hook, "_save_flagged", lambda n, s, r: flagged.append((n, s)))
        monkeypatch.setattr(hook, "_send_alert", lambda *a, **k: None)

        def fake_urlopen(req, timeout=30):
            calls.append(req)
            if http_error:
                code, body = http_error
                raise urllib.error.HTTPError(req.full_url, code, "x", {}, io.BytesIO(json.dumps(body).encode()))
            return _Resp(json.dumps(response).encode())
        monkeypatch.setattr(hook.urllib.request, "urlopen", fake_urlopen)
        done = threading.Event()
        real_thread = threading.Thread

        def sync_thread(target=None, daemon=None, **k):
            class T:
                def start(self_inner):
                    target(); done.set()
            return T()
        monkeypatch.setattr(hook.threading, "Thread", sync_thread)
        hook._background_scan("evilpkg")
        monkeypatch.setattr(hook.threading, "Thread", real_thread)
        return calls, flagged
    return run


def test_h1_hook_uses_get_with_query(scan):
    calls, _ = scan({"verdict": "UNKNOWN"})
    req = calls[0]
    assert req.get_method() == "GET" and req.data is None
    assert "name=evilpkg-dist" in req.full_url and "ecosystem=pip" in req.full_url
    assert req.get_header("Authorization") == "Bearer tok"


def test_h2_blocked_is_flagged_as_dangerous(scan):
    _, flagged = scan({"verdict": "BLOCKED", "reason": "Known malicious"})
    assert flagged == [("evilpkg", "DANGEROUS")]


def test_h2_missing_verdict_is_not_clean_and_not_flagged(scan, monkeypatch, tmp_path):
    monkeypatch.setattr(hook, "SEEN_PATH", tmp_path / "s.json")
    _, flagged = scan({})
    assert flagged == []
    assert hook._import_cache["evilpkg"]["status"] == "UNKNOWN"


def test_h2_suspicious_flagged(scan):
    _, flagged = scan({"verdict": "suspicious"})
    assert flagged == [("evilpkg", "SUSPICIOUS")]


def test_503_body_is_honoured_not_clean(scan):
    _, flagged = scan(http_error=(503, {"verdict": "UNKNOWN", "status": "stale_data"}))
    assert flagged == [] and hook._import_cache["evilpkg"]["status"] == "UNKNOWN"


def test_h3_no_token_warns_and_never_spends_the_free_quota(scan, capsys):
    calls, _ = scan({"verdict": "UNKNOWN"}, token=None)
    assert calls == []                                   # no anonymous import-time calls
    assert "import-time checks are OFF" in capsys.readouterr().err


def test_hook_skips_modules_that_are_not_installed_distributions(scan):
    calls, _ = scan({"verdict": "UNKNOWN"}, dist=None)
    assert calls == []


def test_hook_checks_each_distribution_once_per_day(scan, monkeypatch, tmp_path):
    monkeypatch.setattr(hook, "SEEN_PATH", tmp_path / "seen.json")
    calls, _ = scan({"verdict": "UNKNOWN"})
    assert len(calls) == 1
    calls, _ = scan({"verdict": "UNKNOWN"})              # a new process, same day
    assert calls == []


def test_quota_error_is_not_remembered_as_checked(scan, monkeypatch, tmp_path):
    monkeypatch.setattr(hook, "SEEN_PATH", tmp_path / "seen.json")
    calls, _ = scan(http_error=(429, {"error": "quota"}))
    calls, _ = scan(http_error=(429, {"error": "quota"}))
    assert len(calls) == 1                               # retried, not silenced for 24 h


def test_quota_exhaustion_warns(scan, capsys):
    scan(http_error=(429, {"error": "quota"}))
    assert "quota exhausted" in capsys.readouterr().err


def test_h4_intercept_missing_verdict_is_not_clean():
    src = Path(intercept.__file__).read_text()
    assert 'result.get("verdict", "CLEAN")' not in src
    assert 'verdict in ("DANGEROUS", "BLOCKED")' in src


def _verdict_fn():
    s = cli._WRAPPER_SCRIPT_PIP
    start = s.index("__stillrunning_verdict() {")
    end = s.index("\n}\n", start) + 3
    return s[start:end]


@pytest.mark.parametrize("script", ["pip", "npm"])
def test_wrappers_share_the_verdict_function(script):
    s = cli._WRAPPER_SCRIPT_PIP if script == "pip" else cli._WRAPPER_SCRIPT_NPM
    assert "__stillrunning_verdict \"$pkg\" \"$rc\" || exit 1" in s
    assert "if ! stillrunning scan" not in s


@pytest.mark.parametrize("rc,strict,allowed,msg", [
    (0, "0", True, ""),
    (13, "0", True, ""),
    (10, "0", False, "known malicious"),
    (11, "0", False, "suspicious"),
    (1, "0", True, "NOT checked"),
    (12, "0", True, "quota"),
    (127, "0", True, "not installed"),
    (1, "1", False, "stopped"),
    (127, "1", False, "stopped"),
    (10, "1", False, "known malicious"),
])
def test_wrapper_exit_code_policy(rc, strict, allowed, msg):
    script = _verdict_fn() + f'\n__stillrunning_verdict demo {rc}\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "STILLRUNNING_FAIL_CLOSED": strict})
    assert (r.returncode == 0) is allowed, r.stderr
    assert msg in r.stderr


# ── CLI `stillrunning scan` exit codes (v2.13.7) ─────────────────────────
class _Net:
    """Scripted urlopen: maps a URL substring to a response, HTTPError or exception."""
    def __init__(self, routes):
        self.routes, self.seen = routes, []

    def __call__(self, req, timeout=10):
        url = req.full_url if hasattr(req, "full_url") else req
        self.seen.append(url)
        for key, out in self.routes.items():
            if key in url:
                if isinstance(out, tuple):
                    code, body = out
                    raise urllib.error.HTTPError(url, code, "x", {}, io.BytesIO(json.dumps(body).encode()))
                if isinstance(out, Exception):
                    raise out
                return _Resp(json.dumps(out).encode())
        raise AssertionError(f"unexpected URL {url}")


@pytest.fixture
def cli_scan(monkeypatch):
    monkeypatch.setattr(cli, "Path", cli.Path)
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda c: Path("/nonexistent-home")))
    monkeypatch.setattr("stillrunning.hook._get_api_token", lambda: None)
    def run(routes, npm=False):
        net = _Net(routes)
        monkeypatch.setattr(urllib.request, "urlopen", net)
        rc = cli._scan_package("somepkg", npm=npm)
        return rc, net.seen
    return run


def test_scan_blocked_by_api_before_registry(cli_scan):
    rc, seen = cli_scan({"check-package": {"verdict": "BLOCKED", "reason": "delisted malware"}})
    assert rc == cli.EXIT_BLOCKED and not any("pypi.org" in u for u in seen)


def test_scan_quota_is_12_not_clean(cli_scan):
    rc, _ = cli_scan({"check-package": (429, {"error": "quota"})})
    assert rc == cli.EXIT_RATE_LIMITED == 12


def test_scan_offline_is_1_not_clean(cli_scan):
    rc, _ = cli_scan({"check-package": urllib.error.URLError("down")})
    assert rc == cli.EXIT_ERROR


def test_scan_stale_data_is_1(cli_scan):
    rc, _ = cli_scan({"check-package": (503, {"verdict": "UNKNOWN", "status": "stale_data"})})
    assert rc == cli.EXIT_ERROR


def test_scan_not_on_registry_is_3(cli_scan):
    rc, _ = cli_scan({"check-package": {"verdict": "UNKNOWN"}, "pypi.org": (404, {})})
    assert rc == cli.EXIT_NOT_FOUND == 3


def test_scan_not_on_blocklist_is_0_and_says_so_honestly(cli_scan, capsys):
    rc, _ = cli_scan({"check-package": {"verdict": "UNKNOWN"}, "pypi.org": {"info": {}}})
    out = capsys.readouterr().out
    assert rc == 0 and "not on the blocklist" in out and "CLEAN" not in out


def test_conda_wrapper_uses_the_same_policy():
    assert "__stillrunning_verdict" in cli._CONDA_ACTIVATE_SCRIPT
    assert "if ! stillrunning scan" not in cli._CONDA_ACTIVATE_SCRIPT


def test_wrapper_exit_3_allows_with_a_note():
    script = _verdict_fn() + "\n__stillrunning_verdict demo 3\n"
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "STILLRUNNING_FAIL_CLOSED": "1"})
    assert r.returncode == 0 and "not on the public registry" in r.stderr
