import io
import json
import urllib.error

import pytest

from sweepsafe.chains.transport import TransportError, UrllibTransport, check_url


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def patch_urlopen(monkeypatch, behaviour):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return behaviour(request)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return captured


def test_check_url_rules():
    check_url("https://rpc.example")
    check_url("http://localhost:8545")
    check_url("http://127.0.0.1:8545")
    for bad in ("http://rpc.example", "file:///etc/passwd", "ftp://x.example", "https://", "x"):
        with pytest.raises(TransportError) as info:
            check_url(bad)
        assert not info.value.retriable


def test_post_json_round_trip(monkeypatch):
    captured = patch_urlopen(monkeypatch, lambda r: FakeResponse(b'{"result": "0x1"}'))
    out = UrllibTransport().post_json("https://rpc.example", {"a": 1}, timeout=7)
    assert out == {"result": "0x1"}
    request = captured["request"]
    assert json.loads(request.data) == {"a": 1}
    assert request.get_header("Content-type") == "application/json"
    assert "sweepsafe" in request.get_header("User-agent")
    assert captured["timeout"] == 7


def test_get_json_has_no_body(monkeypatch):
    captured = patch_urlopen(monkeypatch, lambda r: FakeResponse(b"[1,2]"))
    assert UrllibTransport().get_json("https://x.example/list", timeout=5) == [1, 2]
    assert captured["request"].data is None


@pytest.mark.parametrize(
    ("code", "retriable"), [(404, False), (429, True), (500, True), (403, False)]
)
def test_http_errors(monkeypatch, code, retriable):
    def boom(request):
        raise urllib.error.HTTPError(request.full_url, code, "x", {}, None)

    patch_urlopen(monkeypatch, boom)
    with pytest.raises(TransportError) as info:
        UrllibTransport().get_json("https://x.example", timeout=1)
    assert info.value.status == code
    assert info.value.retriable is retriable


def test_network_errors_are_retriable(monkeypatch):
    def boom(request):
        raise urllib.error.URLError("dns")

    patch_urlopen(monkeypatch, boom)
    with pytest.raises(TransportError) as info:
        UrllibTransport().get_json("https://x.example", timeout=1)
    assert info.value.retriable

    def slow(request):
        raise TimeoutError

    patch_urlopen(monkeypatch, slow)
    with pytest.raises(TransportError):
        UrllibTransport().get_json("https://x.example", timeout=1)


def test_invalid_json_and_oversize(monkeypatch):
    patch_urlopen(monkeypatch, lambda r: FakeResponse(b"<html>nope</html>"))
    with pytest.raises(TransportError, match="invalid JSON"):
        UrllibTransport().get_json("https://x.example", timeout=1)

    patch_urlopen(monkeypatch, lambda r: FakeResponse(b"[" + b"1," * 50 + b"1]"))
    with pytest.raises(TransportError, match="exceeded"):
        UrllibTransport(max_bytes=20).get_json("https://x.example", timeout=1)


def test_refuses_insecure_urls_before_any_request(monkeypatch):
    def must_not_run(request):
        raise AssertionError("network touched")

    patch_urlopen(monkeypatch, must_not_run)
    with pytest.raises(TransportError):
        UrllibTransport().get_json("http://evil.example", timeout=1)
