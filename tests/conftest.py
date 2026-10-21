"""Test isolation for the published client (v2.13.7).

A test run once burned this box's free API quota: importing stillrunning.hook
left the import finder installed and every later import made a real HTTPS
call to stillrunning.io. Nothing in tests may reach the network, write the
user's ~/.stillrunning state, or leave a meta_path finder behind."""
import os
import sys
import urllib.request

import pytest

os.environ["STILLRUNNING_DISABLE"] = "1"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    def _no_network(*a, **k):
        raise RuntimeError("network access is disabled in tests — stub urlopen explicitly")
    monkeypatch.setattr(urllib.request, "urlopen", _no_network)
    monkeypatch.delenv("STILLRUNNING_TOKEN", raising=False)
    if "stillrunning.hook" in sys.modules:
        monkeypatch.setattr(sys.modules["stillrunning.hook"], "SEEN_PATH", tmp_path / "import_checks.json")
    yield
    # never leave a stillrunning finder installed between tests
    sys.meta_path[:] = [f for f in sys.meta_path if "stillrunning" not in type(f).__module__]
