import pytest


@pytest.fixture(autouse=True)
def _no_throttle(monkeypatch):
    """Tests never need to wait between simulated RPC requests."""
    monkeypatch.setenv("SWEEPSAFE_REQUEST_INTERVAL", "0")
    monkeypatch.setenv("SWEEPSAFE_BACKOFF", "0")
    monkeypatch.delenv("SWEEPSAFE_DB", raising=False)
    monkeypatch.delenv("SWEEPSAFE_BLOCKLIST_URLS", raising=False)
