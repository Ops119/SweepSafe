import pytest

from sweepsafe.chains import (
    ChainMismatchError,
    RpcClient,
    RpcError,
    RpcUnavailableError,
    TransportError,
)

URLS = ["https://rpc-a.example", "https://rpc-b.example", "https://rpc-c.example"]


class ScriptedTransport:
    """Returns scripted responses per URL; records every request."""

    def __init__(self, script):
        self.script = script  # url -> list of responses (dict or Exception), consumed in order
        self.requests = []

    def post_json(self, url, payload, *, timeout):
        self.requests.append((url, payload["method"]))
        queue = self.script[url]
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        return item

    def get_json(self, url, *, timeout):  # pragma: no cover - unused here
        raise AssertionError


def ok(result):
    return {"jsonrpc": "2.0", "id": 1, "result": result}


def err(code, message):
    return {"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}}


def make(script, **kwargs):
    sleeps = []
    client = RpcClient(
        kwargs.pop("urls", URLS),
        ScriptedTransport(script),
        min_interval=0,
        sleep=sleeps.append,
        **kwargs,
    )
    return client, sleeps


def test_success_returns_result():
    client, _ = make({URLS[0]: [ok("0x10")]})
    assert client.block_number() == 16


def test_rotates_on_rate_limit_and_backs_off():
    client, sleeps = make(
        {
            URLS[0]: [TransportError("HTTP 429", status=429)],
            URLS[1]: [err(-32005, "rate limit exceeded"), ok("0x2")],
            URLS[2]: [ok("0x2")],
        },
        backoff=1.0,
    )
    assert client.block_number() == 2
    assert [u for u, _ in client.transport.requests] == [URLS[0], URLS[1], URLS[2]]
    assert sleeps == [1.0, 2.0]  # exponential backoff between attempts


def test_gives_up_after_retries():
    client, _ = make({u: [TransportError("boom")] for u in URLS}, retries=2)
    with pytest.raises(RpcUnavailableError):
        client.block_number()
    assert len(client.transport.requests) == 3


def test_revert_is_not_retried():
    client, _ = make({URLS[0]: [err(3, "execution reverted")]})
    with pytest.raises(RpcError) as info:
        client.call("eth_call", [{}, "latest"])
    assert info.value.is_revert
    assert len(client.transport.requests) == 1


def test_range_error_is_not_retried_but_flagged():
    client, _ = make({URLS[0]: [err(-32602, "query exceeds max block range 10000")]})
    with pytest.raises(RpcError) as info:
        client.get_logs(0, 100000, [])
    assert info.value.is_range_error
    assert not info.value.retriable
    assert len(client.transport.requests) == 1


def test_non_retriable_transport_error_propagates():
    client, _ = make({URLS[0]: [TransportError("bad", retriable=False)]})
    with pytest.raises(TransportError):
        client.block_number()


def test_chain_mismatch_provider_is_skipped():
    client, _ = make(
        {
            URLS[0]: [ok("0x89")],  # polygon, wrong chain
            URLS[1]: [ok("0x1"), ok("0x20")],
        },
        urls=URLS[:2],
        expected_chain_id=1,
    )
    assert client.block_number() == 32
    methods = [m for _, m in client.transport.requests]
    assert methods == ["eth_chainId", "eth_chainId", "eth_blockNumber"]
    # The bad provider is never used again.
    assert client.block_number() == 32
    assert all(u == URLS[1] for u, _ in client.transport.requests[2:])


def test_all_providers_wrong_chain_raises():
    client, _ = make(
        {URLS[0]: [ok("0x89")], URLS[1]: [ok("0x89")]}, urls=URLS[:2], expected_chain_id=1
    )
    with pytest.raises(ChainMismatchError):
        client.block_number()


def test_malformed_responses_are_retriable():
    client, _ = make({URLS[0]: ["not a dict", ok("0x5")], URLS[1]: [ok("0x5")]})
    assert client.block_number() == 5


def test_missing_result_key_is_an_error():
    client, _ = make({u: [{"jsonrpc": "2.0", "id": 1}] for u in URLS}, retries=1)
    with pytest.raises(RpcUnavailableError):
        client.block_number()


def test_error_without_dict_shape():
    client, _ = make(
        {URLS[0]: [{"jsonrpc": "2.0", "id": 1, "error": "weird"}], URLS[1]: [ok("0x1")]}
    )
    assert client.block_number() == 1


def test_throttle_spaces_requests():
    sleeps = []
    now = [0.0]
    client = RpcClient(
        URLS[:1],
        ScriptedTransport({URLS[0]: [ok("0x1")]}),
        min_interval=0.5,
        sleep=lambda s: (sleeps.append(s), now.__setitem__(0, now[0] + s)),
        clock=lambda: now[0],
    )
    client.block_number()
    client.block_number()
    assert sleeps and sleeps[0] == pytest.approx(0.5)


def test_requires_urls_and_https():
    transport = ScriptedTransport({})
    with pytest.raises(ValueError):
        RpcClient([], transport)
    with pytest.raises(TransportError):
        RpcClient(["http://insecure.example"], transport)
    RpcClient(["http://localhost:8545"], transport)  # local dev nodes are fine


def test_typed_helpers_validate_shapes():
    client, _ = make({URLS[0]: [ok("not-a-list")]})
    with pytest.raises(TransportError):
        client.get_logs(0, 1, [])
    client, _ = make({URLS[0]: [ok(5)]})
    with pytest.raises(TransportError):
        client.eth_call("0x" + "aa" * 20, "0x")
    client, _ = make({URLS[0]: [ok(5)]})
    with pytest.raises(TransportError):
        client.get_code("0x" + "aa" * 20)
    client, _ = make({URLS[0]: [ok(None)]})
    with pytest.raises(TransportError):
        client.get_block_timestamp(10)


def test_typed_helpers_happy_path():
    client, _ = make(
        {URLS[0]: [ok([{"x": 1}]), ok("0xdead"), ok("0x6080"), ok({"timestamp": "0x64"})]}
    )
    assert client.get_logs(1, 2, ["0x1"]) == [{"x": 1}]
    assert client.eth_call("0x" + "aa" * 20, "0x") == "0xdead"
    assert client.get_code("0x" + "aa" * 20) == "0x6080"
    assert client.get_block_timestamp(5) == 100


def test_rpc_error_classification():
    assert RpcError(-32000, "header not found").retriable
    assert RpcError(-32000, "daily request limit reached, rate limit").retriable
    assert not RpcError(-32602, "invalid params").retriable
    assert RpcError(-32000, "Log response size exceeded").is_range_error
    assert RpcError(3, "").is_revert
