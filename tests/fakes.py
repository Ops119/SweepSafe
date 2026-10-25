"""Test doubles: a tiny simulated EVM node and a transport that speaks JSON-RPC to it."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sweepsafe.abi import (
    APPROVAL_TOPIC,
    SELECTOR_ALLOWANCE,
    SELECTOR_DECIMALS,
    SELECTOR_SYMBOL,
    address_to_topic,
    encode_uint256,
)
from sweepsafe.chains.rpc import RpcError
from sweepsafe.chains.transport import TransportError

OWNER = "0x" + "11" * 20
TOKEN_A = "0x" + "aa" * 20
TOKEN_B = "0x" + "bb" * 20
SPENDER_1 = "0x" + "c1" * 20
SPENDER_2 = "0x" + "c2" * 20
SPENDER_3 = "0x" + "c3" * 20
MAX_UINT = (1 << 256) - 1
CONTRACT_CODE = "0x6080604052"


def abi_string(text: str) -> str:
    raw = text.encode()
    padded = raw.ljust(((len(raw) + 31) // 32) * 32, b"\x00")
    return "0x" + (32).to_bytes(32, "big").hex() + len(raw).to_bytes(32, "big").hex() + padded.hex()


def make_log(
    token: str,
    owner: str,
    spender: str,
    value: int,
    block: int,
    log_index: int = 0,
    tx: str | None = None,
) -> dict[str, Any]:
    return {
        "address": token,
        "topics": [APPROVAL_TOPIC, address_to_topic(owner), address_to_topic(spender)],
        "data": "0x" + encode_uint256(value),
        "blockNumber": hex(block),
        "logIndex": hex(log_index),
        "transactionHash": tx or "0x" + f"{block:032x}{log_index:032x}",
        "removed": False,
    }


class FakeNode:
    """Implements the ``ChainReader`` protocol against in-memory chain state."""

    def __init__(
        self,
        head: int = 1_000,
        logs: Sequence[dict[str, Any]] = (),
        allowances: dict[tuple[str, str], int] | None = None,
        tokens: dict[str, tuple[str, int]] | None = None,
        codes: dict[str, str] | None = None,
        timestamps: dict[int, int] | None = None,
        max_range: int | None = None,
    ) -> None:
        self.head = head
        self.logs = list(logs)
        self.allowances = allowances or {}
        self.tokens = tokens or {}
        self.codes = codes or {}
        self.timestamps = timestamps or {}
        self.max_range = max_range
        self.log_requests: list[tuple[int, int]] = []
        self.calls: list[tuple[str, str]] = []

    def block_number(self) -> int:
        return self.head

    def get_logs(self, from_block: int, to_block: int, topics: Sequence[str | None]) -> list[dict]:
        self.log_requests.append((from_block, to_block))
        if self.max_range is not None and to_block - from_block + 1 > self.max_range:
            raise RpcError(-32602, "query exceeds max block range of 10000")
        owner_topic = topics[1]
        return [
            lg
            for lg in self.logs
            if from_block <= int(lg["blockNumber"], 16) <= to_block
            and lg["topics"][0] == topics[0]
            and (owner_topic is None or lg["topics"][1] == owner_topic)
        ]

    def eth_call(self, to: str, data: str, block: str = "latest") -> str:
        self.calls.append((to, data[:10]))
        selector = data[:10]
        if selector == SELECTOR_ALLOWANCE:
            spender = "0x" + data[10 + 64 + 24 :]
            if (to, spender) in self.allowances:
                return "0x" + encode_uint256(self.allowances[(to, spender)])
            raise RpcError(3, "execution reverted")
        if selector == SELECTOR_SYMBOL and to in self.tokens:
            return abi_string(self.tokens[to][0])
        if selector == SELECTOR_DECIMALS and to in self.tokens:
            return "0x" + encode_uint256(self.tokens[to][1])
        raise RpcError(3, "execution reverted")

    def get_code(self, address: str) -> str:
        return self.codes.get(address, "0x")

    def get_block_timestamp(self, block_number: int) -> int:
        if block_number not in self.timestamps:
            raise RpcError(-32000, "header not found")
        return self.timestamps[block_number]


class NodeTransport:
    """Speaks JSON-RPC over the Transport interface by delegating to a ``FakeNode``.

    ``get_json`` serves the free APIs: blocklists and contract-verification lookups.
    """

    def __init__(
        self,
        node: FakeNode,
        chain_id: int = 1,
        blocklists: dict[str, Any] | None = None,
        verified: set[str] | None = None,
    ) -> None:
        self.node = node
        self.chain_id = chain_id
        self.blocklists = blocklists or {}
        self.verified = {a.lower() for a in (verified or set())}
        self.gets: list[str] = []

    def post_json(self, url: str, payload: Any, *, timeout: float) -> Any:
        method, params = payload["method"], payload["params"]
        try:
            if method == "eth_chainId":
                result: Any = hex(self.chain_id)
            elif method == "eth_blockNumber":
                result = hex(self.node.block_number())
            elif method == "eth_getLogs":
                flt = params[0]
                result = self.node.get_logs(
                    int(flt["fromBlock"], 16), int(flt["toBlock"], 16), flt["topics"]
                )
            elif method == "eth_call":
                result = self.node.eth_call(params[0]["to"], params[0]["data"])
            elif method == "eth_getCode":
                result = self.node.get_code(params[0])
            elif method == "eth_getBlockByNumber":
                result = {"timestamp": hex(self.node.get_block_timestamp(int(params[0], 16)))}
            else:
                raise RpcError(-32601, "method not found")
        except RpcError as exc:
            return {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "error": {"code": exc.code, "message": exc.message},
            }
        return {"jsonrpc": "2.0", "id": payload["id"], "result": result}

    def get_json(self, url: str, *, timeout: float) -> Any:
        self.gets.append(url)
        if url in self.blocklists:
            return self.blocklists[url]
        if "/contract/" in url or "/smart-contracts/" in url:
            address = url.rsplit("/", 1)[-1].lower()
            if address in self.verified:
                return {"is_verified": True, "match": "exact_match"}
            raise TransportError("not found", status=404, retriable=False)
        raise TransportError("not found", status=404, retriable=False)
