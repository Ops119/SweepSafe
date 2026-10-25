"""JSON-RPC client with provider rotation, retries, exponential backoff and throttling."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from sweepsafe.abi import decode_hex_int
from sweepsafe.chains.transport import Transport, TransportError, check_url

_RANGE_HINTS = (
    "block range",
    "blocks range",
    "range is too",
    "range too",
    "too many results",
    "more than 10000 results",
    "response size",
    "query returned more than",
    "max results",
    "eth_getlogs is limited",
    "limited to",
    "exceeds the range",
    "exceed maximum",
)
_RATE_HINTS = ("rate limit", "too many requests", "429", "capacity", "request limit", "throttl")
_REVERT_HINTS = ("revert", "invalid opcode", "out of gas")


class RpcError(Exception):
    """A JSON-RPC level error returned by a node."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data

    @property
    def is_range_error(self) -> bool:
        """The node refused the request because the block range / result set was too large."""
        text = self.message.lower()
        return any(hint in text for hint in _RANGE_HINTS)

    @property
    def is_revert(self) -> bool:
        text = self.message.lower()
        return self.code == 3 or any(hint in text for hint in _REVERT_HINTS)

    @property
    def retriable(self) -> bool:
        """Worth retrying on another provider (rate limits, node hiccups)."""
        if self.is_range_error or self.is_revert:
            return False
        text = self.message.lower()
        if any(hint in text for hint in _RATE_HINTS):
            return True
        return self.code in (-32005, -32603, -32000, -32002)


class RpcUnavailableError(Exception):
    """Every configured provider failed."""


class ChainMismatchError(Exception):
    """A provider reported a different chain id than expected."""


class ChainReader(Protocol):
    """What the scanner needs from a node. ``RpcClient`` implements this; tests use fakes."""

    def block_number(self) -> int: ...

    def get_logs(
        self, from_block: int, to_block: int, topics: Sequence[str | None]
    ) -> list[dict]: ...

    def eth_call(self, to: str, data: str, block: str = "latest") -> str: ...

    def get_code(self, address: str) -> str: ...

    def get_block_timestamp(self, block_number: int) -> int: ...


class RpcClient:
    def __init__(
        self,
        urls: Sequence[str],
        transport: Transport,
        *,
        expected_chain_id: int | None = None,
        retries: int = 3,
        backoff: float = 0.75,
        min_interval: float = 0.15,
        timeout: float = 20.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not urls:
            raise ValueError("at least one RPC URL is required")
        for url in urls:
            check_url(url)
        self.urls = list(urls)
        self.transport = transport
        self.expected_chain_id = expected_chain_id
        self.retries = retries
        self.backoff = backoff
        self.min_interval = min_interval
        self.timeout = timeout
        self._sleep = sleep
        self._clock = clock
        self._index = 0
        self._next_id = 1
        self._last_request = float("-inf")
        self._verified: set[str] = set()
        self._bad: set[str] = set()

    # -- core --------------------------------------------------------------------------------
    @property
    def current_url(self) -> str:
        return self.urls[self._index]

    def _rotate(self) -> None:
        for step in range(1, len(self.urls) + 1):
            candidate = (self._index + step) % len(self.urls)
            if self.urls[candidate] not in self._bad:
                self._index = candidate
                return

    def _throttle(self) -> None:
        wait = self.min_interval - (self._clock() - self._last_request)
        if wait > 0:
            self._sleep(wait)
        self._last_request = self._clock()

    def _request(self, url: str, method: str, params: list[Any]) -> Any:
        self._throttle()
        payload = {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
        self._next_id += 1
        response = self.transport.post_json(url, payload, timeout=self.timeout)
        if not isinstance(response, dict):
            raise TransportError(f"malformed JSON-RPC response from {url}")
        error = response.get("error")
        if error is not None:
            if isinstance(error, dict):
                raise RpcError(
                    int(error.get("code", -32000)), str(error.get("message", "")), error.get("data")
                )
            raise RpcError(-32000, str(error))
        if "result" not in response:
            raise TransportError(f"JSON-RPC response from {url} has no result")
        return response["result"]

    def _ensure_chain(self, url: str) -> None:
        if self.expected_chain_id is None or url in self._verified:
            return
        actual = decode_hex_int(self._request(url, "eth_chainId", []))
        if actual != self.expected_chain_id:
            self._bad.add(url)
            raise ChainMismatchError(f"{url} is chain {actual}, expected {self.expected_chain_id}")
        self._verified.add(url)

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        params = params or []
        attempts = max(self.retries + 1, 1)
        last: Exception | None = None
        for attempt in range(attempts):
            if all(u in self._bad for u in self.urls):
                raise ChainMismatchError(f"no RPC provider serves chain {self.expected_chain_id}")
            url = self.current_url
            mismatch = False
            try:
                self._ensure_chain(url)
                return self._request(url, method, params)
            except RpcError as exc:
                if not exc.retriable:
                    raise
                last = exc
            except TransportError as exc:
                if not exc.retriable:
                    raise
                last = exc
            except ChainMismatchError as exc:
                last = exc
                mismatch = True
            self._rotate()
            if not mismatch and attempt < attempts - 1:
                self._sleep(self.backoff * (2**attempt))
        raise RpcUnavailableError(f"all RPC attempts failed for {method}: {last}") from last

    # -- typed helpers -----------------------------------------------------------------------
    def block_number(self) -> int:
        return decode_hex_int(self.call("eth_blockNumber"))

    def get_logs(self, from_block: int, to_block: int, topics: Sequence[str | None]) -> list[dict]:
        flt = {"fromBlock": hex(from_block), "toBlock": hex(to_block), "topics": list(topics)}
        result = self.call("eth_getLogs", [flt])
        if not isinstance(result, list):
            raise TransportError("eth_getLogs returned a non-list result")
        return result

    def eth_call(self, to: str, data: str, block: str = "latest") -> str:
        result = self.call("eth_call", [{"to": to, "data": data}, block])
        if not isinstance(result, str):
            raise TransportError("eth_call returned a non-string result")
        return result

    def get_code(self, address: str) -> str:
        result = self.call("eth_getCode", [address, "latest"])
        if not isinstance(result, str):
            raise TransportError("eth_getCode returned a non-string result")
        return result

    def get_block_timestamp(self, block_number: int) -> int:
        block = self.call("eth_getBlockByNumber", [hex(block_number), False])
        if not isinstance(block, dict) or "timestamp" not in block:
            raise TransportError(f"block {block_number} not available")
        return decode_hex_int(block["timestamp"])
