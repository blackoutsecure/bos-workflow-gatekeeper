import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


@pytest.fixture(autouse=True)
def deny_live_network(monkeypatch):
    def unexpected_request(*args, **kwargs):
        raise AssertionError("Offline tests must mock the GitHub API transport.")

    monkeypatch.setattr(urllib.request, "urlopen", unexpected_request)
