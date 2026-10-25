"""Chunked ``eth_getLogs`` for ERC-20 ``Approval`` events with adaptive block ranges."""

from __future__ import annotations

from collections.abc import Callable, Iterator

from sweepsafe.abi import (
    APPROVAL_TOPIC,
    AbiError,
    address_to_topic,
    decode_hex_int,
    normalize_address,
    topic_to_address,
)
from sweepsafe.chains.rpc import ChainReader, RpcError
from sweepsafe.models import ApprovalLog

INITIAL_CHUNK = 100_000
MIN_CHUNK = 250
MAX_CHUNK = 5_000_000
DENSE_LOGS = 2_000  # shrink the next request if a chunk returned this many logs
SPARSE_LOGS = 200  # grow the next request if a chunk returned fewer than this


class ScanError(Exception):
    """The scan could not complete (e.g. node refuses even the smallest block range)."""


def parse_approval_log(entry: dict, owner: str) -> ApprovalLog | None:
    """Turn a raw log into an ``ApprovalLog``; None for anything that is not an ERC-20 approval.

    ERC-721 ``Approval`` events share the same topic0 but have four topics, so the topic count
    is what separates them. Removed (reorged) logs and malformed entries are ignored.
    """
    try:
        if entry.get("removed"):
            return None
        topics = entry["topics"]
        if len(topics) != 3 or str(topics[0]).lower() != APPROVAL_TOPIC:
            return None
        if topic_to_address(topics[1]) != owner:
            return None
        data = entry["data"]
        if not isinstance(data, str) or len(data) != 66:
            return None
        return ApprovalLog(
            token=normalize_address(entry["address"]),
            spender=topic_to_address(topics[2]),
            value=int(data, 16),
            block_number=decode_hex_int(entry["blockNumber"]),
            log_index=decode_hex_int(entry["logIndex"]),
            tx_hash=str(entry["transactionHash"]).lower(),
        )
    except (KeyError, TypeError, ValueError, AbiError):
        return None


def fetch_approval_logs(
    reader: ChainReader,
    owner: str,
    from_block: int,
    to_block: int,
    *,
    initial_chunk: int = INITIAL_CHUNK,
    min_chunk: int = MIN_CHUNK,
    max_chunk: int = MAX_CHUNK,
    progress: Callable[[int, int], None] | None = None,
) -> Iterator[tuple[int, int, list[ApprovalLog]]]:
    """Yield ``(chunk_from, chunk_to, logs)`` for each successfully fetched block range.

    The range halves when a node rejects it as too large (or returns a dense result) and doubles
    again over sparse stretches, so the same code works on strict and generous public RPCs.
    Yielding per chunk lets the caller persist progress and resume after an interruption.
    """
    owner = normalize_address(owner)
    topics = [APPROVAL_TOPIC, address_to_topic(owner)]
    chunk = max(min_chunk, min(initial_chunk, max_chunk))
    start = from_block
    while start <= to_block:
        end = min(start + chunk - 1, to_block)
        try:
            raw = reader.get_logs(start, end, topics)
        except RpcError as exc:
            if exc.is_range_error and chunk > min_chunk:
                chunk = max(min_chunk, chunk // 2)
                continue
            if exc.is_range_error:
                raise ScanError(
                    f"node rejects even a {min_chunk}-block range "
                    f"(blocks {start}-{end}): {exc.message}"
                ) from exc
            raise
        logs = [lg for entry in raw if (lg := parse_approval_log(entry, owner)) is not None]
        yield start, end, logs
        if progress is not None:
            progress(end, to_block)
        start = end + 1
        if len(raw) >= DENSE_LOGS:
            chunk = max(min_chunk, chunk // 2)
        elif len(raw) < SPARSE_LOGS:
            chunk = min(max_chunk, chunk * 2)
