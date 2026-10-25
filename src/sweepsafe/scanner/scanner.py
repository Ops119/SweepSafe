"""Collect a wallet's currently-active ERC-20 approvals (logs -> live allowance -> metadata)."""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable

from sweepsafe.abi import (
    SELECTOR_DECIMALS,
    SELECTOR_SYMBOL,
    AbiError,
    decode_string,
    decode_uint256,
    encode_allowance_call,
    normalize_address,
)
from sweepsafe.chains.rpc import ChainReader, RpcError
from sweepsafe.config.chains import Chain
from sweepsafe.models import Approval, ApprovalLog
from sweepsafe.scanner.logs import fetch_approval_logs
from sweepsafe.store import Store


class Scanner:
    def __init__(
        self,
        chain: Chain,
        reader: ChainReader,
        store: Store,
        *,
        progress: Callable[[int, int], None] | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.chain = chain
        self.reader = reader
        self.store = store
        self.progress = progress
        self._now = now
        self.warnings: list[str] = []

    # -- step 1: sync raw approval logs, resumably ------------------------------------------
    def sync_logs(self, owner: str, *, from_block: int | None = None, reset: bool = False) -> int:
        """Fetch new ``Approval`` logs into the cache; returns the block scanned up to."""
        owner = normalize_address(owner)
        chain_id = self.chain.chain_id
        head = self.reader.block_number()

        if reset:
            self.store.reset_wallet(chain_id, owner)
        cursor = self.store.get_cursor(chain_id, owner)

        requested_start = self.chain.start_block if from_block is None else max(0, from_block)
        if cursor is not None and requested_start < cursor[0]:
            # Caller wants older history than we ever scanned: start over, keep results honest.
            self.store.reset_wallet(chain_id, owner)
            cursor = None

        if cursor is None:
            first_block, start = requested_start, requested_start
        else:
            first_block = cursor[0]
            # Re-scan the tail so a shallow reorg cannot leave logs from orphaned blocks behind.
            start = max(first_block, cursor[1] - self.chain.reorg_depth + 1)

        if first_block > self.chain.start_block:
            self.warnings.append(
                f"History before block {first_block} was not scanned; "
                "approvals granted earlier will not appear."
            )
        if start > head:
            return cursor[1] if cursor else head

        self.store.delete_logs_from(chain_id, owner, start)
        for _chunk_from, chunk_to, logs in fetch_approval_logs(
            self.reader, owner, start, head, progress=self.progress
        ):
            self.store.add_logs(chain_id, owner, logs)
            self.store.set_cursor(chain_id, owner, first_block, chunk_to)
        return head

    # -- step 2: resolve which approvals are still live -------------------------------------
    def active_approvals(self, owner: str) -> list[Approval]:
        owner = normalize_address(owner)
        latest: dict[tuple[str, str], ApprovalLog] = {}
        for log in self.store.get_logs(self.chain.chain_id, owner):
            key = (log.token, log.spender)
            if key not in latest or log.order_key > latest[key].order_key:
                latest[key] = log

        approvals: list[Approval] = []
        for (token, spender), log in sorted(latest.items(), key=lambda kv: kv[1].order_key):
            if log.value == 0:
                continue  # last event set it to zero
            allowance = self._live_allowance(owner, token, spender)
            if not allowance:
                continue
            symbol, decimals = self._token_meta(token)
            approvals.append(
                Approval(
                    chain=self.chain.name,
                    owner=owner,
                    token=token,
                    spender=spender,
                    allowance=allowance,
                    block_number=log.block_number,
                    tx_hash=log.tx_hash,
                    timestamp=self._block_timestamp(log.block_number),
                    token_symbol=symbol,
                    token_decimals=decimals,
                )
            )
        return approvals

    # -- helpers ----------------------------------------------------------------------------
    def _live_allowance(self, owner: str, token: str, spender: str) -> int | None:
        """The on-chain allowance right now (the event value may be stale after spending)."""
        try:
            return decode_uint256(
                self.reader.eth_call(token, encode_allowance_call(owner, spender))
            )
        except (RpcError, AbiError) as exc:
            self.warnings.append(
                f"Could not read allowance for token {token} ({_brief(exc)}); skipped."
            )
            return None

    def _token_meta(self, token: str) -> tuple[str | None, int | None]:
        cached = self.store.get_token_meta(self.chain.chain_id, token)
        if cached is not None:
            return cached
        symbol: str | None = None
        decimals: int | None = None
        with contextlib.suppress(RpcError):
            symbol = decode_string(self.reader.eth_call(token, SELECTOR_SYMBOL))
        try:
            value = decode_uint256(self.reader.eth_call(token, SELECTOR_DECIMALS))
            decimals = value if value <= 255 else None
        except (RpcError, AbiError):
            pass
        self.store.set_token_meta(self.chain.chain_id, token, symbol, decimals)
        return symbol, decimals

    def _block_timestamp(self, block_number: int) -> int | None:
        cached = self.store.get_block_ts(self.chain.chain_id, block_number)
        if cached is not None:
            return cached
        try:
            timestamp = self.reader.get_block_timestamp(block_number)
        except Exception as exc:  # noqa: BLE001 - age is a nice-to-have, never fatal
            self.warnings.append(
                f"Could not read the date of block {block_number} ({_brief(exc)})."
            )
            return None
        self.store.set_block_ts(self.chain.chain_id, block_number, timestamp)
        return timestamp


def _brief(exc: Exception) -> str:
    text = str(exc).strip().replace("\n", " ")
    return text[:80] or exc.__class__.__name__
