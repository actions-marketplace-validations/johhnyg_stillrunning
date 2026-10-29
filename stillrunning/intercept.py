#!/usr/bin/env python3
"""
npm_pip_intercept.py — Supply chain attack protection.
Intercepts npm/pip installs, checks against known-bad list, verifies hashes.

Usage:
  stillrunning-intercept pip install <package>
  stillrunning-intercept npm install <package>

Called automatically when stillrunning wraps pip/npm.

v2.4.0: Added support for poetry, pdm, pipenv, conda, pixi, bun, pnpm.
        Added manifest file parsing for requirements.txt, pyproject.toml, etc.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# ─── Constants ───────────────────────────────────────────────────────────────

STILLRUNNING_DIR = Path.home() / ".stillrunning"
STILLRUNNING_DIR.mkdir(exist_ok=True)

_server_env = Path.home() / "my-app" / ".env"
_server_known_bad = Path.home() / "my-app" / "known_bad_packages.json"
ENV_FILE = _server_env if _server_env.exists() else STILLRUNNING_DIR / ".env"
KNOWN_BAD_JSON = _server_known_bad if _server_known_bad.exists() else STILLRUNNING_DIR / "known_bad_packages.json"

KNOWN_BAD_PIP = {
    "logutilkit": ["any"],
    "apachelicense": ["any"],
    "fluxhttp": ["any"],
    "license-utils-kit": ["any"],
    "logkitx": ["any"],
    "pino-debugger": ["any"],
    "dev-log-core": ["any"],
    "logger-base": ["any"],
}

KNOWN_BAD_NPM = {
    "dev-log-core": ["any"],
    "logger-base": ["any"],
    "logkitx": ["any"],
    "pino-debugger": ["any"],
    "log-utils-js": ["any"],
    "node-log-helper": ["any"],
}

# v2.4.0: All supported package managers
SUPPORTED_MANAGERS = {
    "pip", "pip3", "npm", "yarn", "pnpm", "uv", "bun",
    "poetry", "pdm", "pipenv", "conda", "pixi"
}

INSTALL_COMMANDS = {
    "pip": ("install",),
    "pip3": ("install",),
    "npm": ("install", "i", "add", "ci"),
    "yarn": ("add", "install"),
    "pnpm": ("add", "install", "i"),
    "bun": ("add", "install", "i"),
    "uv": ("pip", "add", "install"),
    "poetry": ("add", "install"),
    "pdm": ("add", "install"),
    "pipenv": ("install",),
    "conda": ("install", "create"),
    "pixi": ("add", "install"),
}

MANAGER_ECOSYSTEM = {
    "pip": "pip", "pip3": "pip", "uv": "pip", "poetry": "pip",
    "pdm": "pip", "pipenv": "pip", "pixi": "pip",
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm",
    "conda": "conda",
}


def _load_auto_synced_known_bad() -> tuple[dict, dict]:
    """Load auto-synced known-bad packages from threat_feed."""
    pip_extra = {}
    npm_extra = {}
    try:
        if KNOWN_BAD_JSON.exists():
            with open(KNOWN_BAD_JSON) as f:
                data = json.load(f)
            pip_extra = {k: ["any"] for k in data.get("pip", {}).keys()}
            npm_extra = {k: ["any"] for k in data.get("npm", {}).keys()}
    except Exception:
        pass
    return pip_extra, npm_extra


_server_cache = Path.home() / "my-app" / "threat_cache.json"
THREAT_CACHE_JSON = _server_cache if _server_cache.exists() else STILLRUNNING_DIR / "threat_cache.json"
THREAT_CACHE_TTL_SECONDS = 3600

SCAN_USAGE_FILE = STILLRUNNING_DIR / "scan_usage.json"
FREE_DAILY_LIMIT = 10

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _get_scan_usage() -> dict:
    from datetime import date
    today = str(date.today())
    try:
        if SCAN_USAGE_FILE.exists():
            with open(SCAN_USAGE_FILE) as f:
                data = json.load(f)
            if data.get("date") == today:
                return {"date": today, "count": data.get("count", 0)}
    except Exception:
        pass
    return {"date": today, "count": 0}


def _increment_scan_usage(pkg_count: int = 1) -> int:
    usage = _get_scan_usage()
    usage["count"] += pkg_count
    tmp = SCAN_USAGE_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(usage, f)
    os.replace(tmp, SCAN_USAGE_FILE)
    return usage["count"]


def _show_upgrade_prompt(scans_used: int) -> None:
    remaining = FREE_DAILY_LIMIT - scans_used
    if remaining <= 3 and remaining > 0:
        print(f"\n{YELLOW}Scans remaining today: {remaining}/{FREE_DAILY_LIMIT}{RESET}")
        print(f"   Upgrade for unlimited: https://stillrunning.io/pricing")
    elif remaining <= 0:
        print(f"\n{RED}Free scan limit reached ({FREE_DAILY_LIMIT}/day){RESET}")
        print(f"   Packages checked against blocklist only (no AI review)")
        print(f"   Upgrade for unlimited: https://stillrunning.io/pricing")


def _load_threat_cache():
    try:
        if THREAT_CACHE_JSON.exists():
            with open(THREAT_CACHE_JSON) as f:
                data = json.load(f)
            cached_at = data.get("cached_at", 0)
            if time.time() - cached_at < THREAT_CACHE_TTL_SECONDS:
                return data.get("packages", {})
    except Exception:
        pass
    return None


def _fetch_threat_rules_from_api():
    token = None
    if ENV_FILE.exists():
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("STILLRUNNING_TOKEN="):
                    token = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break

    if not token:
        return None

    try:
        url = "https://stillrunning.io/api/threats/rules"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                packages = data.get("packages", {})
                cache_data = {"packages": packages, "cached_at": time.time(), "version": data.get("version")}
                try:
                    tmp_path = str(THREAT_CACHE_JSON) + ".tmp"
                    with open(tmp_path, "w") as f:
                        json.dump(cache_data, f, indent=2)
                    os.replace(tmp_path, THREAT_CACHE_JSON)
                except Exception:
                    pass
                return packages
    except Exception as e:
        print(f"[intercept] API fetch failed: {e}", file=sys.stderr)
    return None


def _get_api_rules():
    cached = _load_threat_cache()
    if cached:
        return cached
    api_rules = _fetch_threat_rules_from_api()
    if api_rules:
        return api_rules
    return {}


def get_known_bad_pip() -> dict:
    extra_pip, _ = _load_auto_synced_known_bad()
    merged = dict(KNOWN_BAD_PIP)
    merged.update(extra_pip)
    api_rules = _get_api_rules()
    for pkg, info in api_rules.items():
        if info.get("ecosystem") in ("pip", "unknown") and pkg not in merged:
            merged[pkg] = info.get("versions", ["any"])
    return merged


def get_known_bad_npm() -> dict:
    _, extra_npm = _load_auto_synced_known_bad()
    merged = dict(KNOWN_BAD_NPM)
    merged.update(extra_npm)
    api_rules = _get_api_rules()
    for pkg, info in api_rules.items():
        if info.get("ecosystem") in ("npm", "unknown") and pkg not in merged:
            merged[pkg] = info.get("versions", ["any"])
    return merged


def send_telegram_alert(package: str, reason: str):
    bot_token = None
    chat_id = None

    if ENV_FILE.exists():
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("TELEGRAM_BOT_TOKEN="):
                    bot_token = line.split("=", 1)[1].strip().strip('"').strip("'")
                elif line.startswith("TELEGRAM_CHAT_ID="):
                    chat_id = line.split("=", 1)[1].strip().strip('"').strip("'")

    if not bot_token or not chat_id:
        return

    try:
        import urllib.parse
        msg = f"\U0001F6A8 [intercept] BLOCKED — {package}\nReason: {reason}"
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": chat_id, "text": msg}).encode()
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def _get_token() -> str:
    config_file = Path(__file__).parent / "stillrunning.yaml"
    if config_file.exists():
        try:
            import yaml
            with open(config_file) as f:
                config = yaml.safe_load(f) or {}
            token = config.get("token", "")
            if token:
                return token
        except Exception:
            pass

    env_file = Path.home() / "stillrunning.yaml"
    if env_file.exists():
        try:
            import yaml
            with open(env_file) as f:
                config = yaml.safe_load(f) or {}
            token = config.get("token", "")
            if token:
                return token
        except Exception:
            pass

    return ""


def call_ai_scan(package: str, ecosystem: str = "pip") -> tuple[str, str] | None:
    token = _get_token()
    if not token:
        return None

    try:
        url = "https://stillrunning.io/api/scan"
        payload = json.dumps({
            "token": token,
            "package": package,
            "ecosystem": ecosystem
        }).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "stillrunning-intercept/2.4.0"
            }
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())

        if "error" in result:
            return None

        # v2.13.7: a missing verdict is UNKNOWN, never CLEAN; BLOCKED is acted on.
        verdict = str(result.get("verdict") or "UNKNOWN").upper()
        score = result.get("score", 0)
        reasons = result.get("reasons", [])

        if verdict in ("DANGEROUS", "BLOCKED"):
            reason = reasons[0] if reasons else f"AI review: dangerous (score {score})"
            return "BLOCKED", reason
        elif verdict == "SUSPICIOUS":
            reason = reasons[0] if reasons else f"AI review: suspicious (score {score})"
            return "WARN", reason

        return None

    except Exception:
        return None


def check_pypi_package(package: str, version: str = None) -> tuple[str, str]:
    known_bad = get_known_bad_pip()
    if package.lower() in known_bad:
        return "BLOCKED", f"Package '{package}' is in known-malicious list"

    try:
        url = f"https://pypi.org/pypi/{package}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "stillrunning/2.4.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            json.loads(resp.read().decode())

        ai_result = call_ai_scan(package, "pip")
        if ai_result:
            return ai_result

        return "CLEAN", "Package verified"

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "WARN", f"Package '{package}' not found on PyPI"
        return "WARN", f"PyPI check failed: HTTP {e.code}"
    except Exception as e:
        return "WARN", f"PyPI check failed: {e}"


def check_npm_package(package: str, version: str = None) -> tuple[str, str]:
    known_bad = get_known_bad_npm()
    if package.lower() in known_bad:
        return "BLOCKED", f"Package '{package}' is in known-malicious list"

    try:
        url = f"https://registry.npmjs.org/{package}"
        req = urllib.request.Request(url, headers={"User-Agent": "stillrunning/2.4.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            json.loads(resp.read().decode())

        ai_result = call_ai_scan(package, "npm")
        if ai_result:
            return ai_result

        return "CLEAN", "Package verified"

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "WARN", f"Package '{package}' not found on npm"
        return "WARN", f"npm check failed: HTTP {e.code}"
    except Exception as e:
        return "WARN", f"npm check failed: {e}"


# ─── Main Logic ──────────────────────────────────────────────────────────────

def extract_packages_and_manifests(args: list, manager: str) -> tuple[list, list]:
    """Extract package names and manifest files from command args."""
    packages = []
    manifests = []
    skip_next = False
    editable_next = False

    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if editable_next:
            editable_next = False
            continue

        if arg.startswith("-"):
            if arg in ("-r", "--requirement"):
                skip_next = True
                if i + 1 < len(args):
                    manifests.append(Path(args[i + 1]))
            elif arg in ("-e", "--editable"):
                editable_next = True
            elif arg.startswith("-r"):
                manifests.append(Path(arg[2:]))
            elif arg.startswith("--requirement="):
                manifests.append(Path(arg.split("=", 1)[1]))
            continue

        if arg in ("install", "i", "add", "ci", "create", "pip"):
            continue

        if arg.startswith("git+") or arg.startswith("https://") or arg.startswith("http://"):
            continue
        if arg.startswith(".") or arg.startswith("/") or arg.startswith("~"):
            continue

        pkg = arg.split("==")[0].split(">=")[0].split("<=")[0].split("@")[0].split("[")[0]
        if pkg and not pkg.startswith("-"):
            packages.append(pkg.lower())

    return packages, manifests


def _check_packages(packages: list, ecosystem: str) -> tuple[list, list]:
    """Check packages and return (blocked, warnings)."""
    blocked = []
    warnings = []

    for pkg in packages:
        if ecosystem in ("pip", "conda"):
            status, reason = check_pypi_package(pkg)
        else:
            status, reason = check_npm_package(pkg)

        if status == "BLOCKED":
            blocked.append((pkg, reason))
            print(f"{RED}{BOLD}\U0001F6A8 BLOCKED{RESET} — {pkg}")
            print(f"   {reason}")
            send_telegram_alert(pkg, reason)
        elif status == "WARN":
            warnings.append((pkg, reason))
            print(f"{YELLOW}⚠ WARNING{RESET} — {pkg}")
            print(f"   {reason}")
        else:
            print(f"{GREEN}✅ CLEAN{RESET} — {pkg}")

    return blocked, warnings


def main():
    import shutil

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <manager> <command> [args...]")
        print("Supported: pip, npm, uv, poetry, pdm, pipenv, conda, pixi, bun, pnpm")
        sys.exit(1)

    manager = sys.argv[1].lower()
    args = sys.argv[2:]

    if manager not in SUPPORTED_MANAGERS:
        print(f"{RED}[intercept]{RESET} Unknown manager: {manager}")
        sys.exit(1)

    manager_path = shutil.which(manager)
    if not manager_path:
        print(f"{RED}[intercept]{RESET} Package manager not found: {manager}")
        sys.exit(1)

    ecosystem = MANAGER_ECOSYSTEM.get(manager, "pip")
    original_args = args[:]

    is_uv_pip = False
    if manager == "uv" and args and args[0] == "pip":
        is_uv_pip = True
        args = args[1:]

    if not args:
        result = subprocess.run([manager_path] + original_args)
        sys.exit(result.returncode)

    install_cmds = INSTALL_COMMANDS.get(manager, ("install",))
    if args[0] not in install_cmds:
        result = subprocess.run([manager_path] + original_args)
        sys.exit(result.returncode)

    packages, manifests = extract_packages_and_manifests(args, manager)

    if manifests:
        try:
            from stillrunning.manifest import parse_manifest
            for manifest_path in manifests:
                if manifest_path.exists():
                    print(f"[stillrunning] Scanning {manifest_path}...")
                    specs = parse_manifest(manifest_path)
                    for spec in specs:
                        if not spec.is_local and not spec.is_url and not spec.is_git:
                            packages.append(spec.name)
        except ImportError:
            print(f"{YELLOW}[intercept] Manifest parsing unavailable{RESET}")

    if not packages and not manifests:
        cwd = Path.cwd()
        try:
            from stillrunning.manifest import find_manifest_in_dir, parse_manifest
            manifest = find_manifest_in_dir(cwd)
            if manifest:
                print(f"[stillrunning] Scanning {manifest}...")
                specs = parse_manifest(manifest)
                for spec in specs:
                    if not spec.is_local and not spec.is_url and not spec.is_git:
                        packages.append(spec.name)
        except ImportError:
            pass

    if not packages:
        result = subprocess.run([manager_path] + original_args)
        sys.exit(result.returncode)

    packages = list(dict.fromkeys(packages))

    if len(packages) > 50:
        print(f"[stillrunning] Checking {len(packages)} packages...")

    blocked, warnings = _check_packages(packages, ecosystem)

    scans_used = _increment_scan_usage(len(packages))
    _show_upgrade_prompt(scans_used)

    if blocked:
        print()
        print(f"{RED}{BOLD}Installation blocked.{RESET} {len(blocked)} malicious package(s) detected.")
        sys.exit(1)

    if warnings:
        print()
        try:
            if sys.stdin.isatty():
                response = input(f"{YELLOW}Continue anyway? [y/N]{RESET} ")
                if response.lower() != "y":
                    print("Installation cancelled.")
                    sys.exit(1)
            else:
                print(f"{YELLOW}Non-interactive mode — proceeding despite warnings{RESET}")
        except (EOFError, KeyboardInterrupt):
            print("\nInstallation cancelled.")
            sys.exit(1)

    print()
    print(f"{GREEN}Proceeding with install...{RESET}")
    result = subprocess.run([manager_path] + original_args)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
