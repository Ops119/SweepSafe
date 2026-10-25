import pytest

from fakes import (
    CONTRACT_CODE,  # noqa: F401
    MAX_UINT,
    OWNER,
    SPENDER_1,
    SPENDER_2,
    TOKEN_A,
    TOKEN_B,
    FakeNode,
    make_log,
)
from sweepsafe.abi import APPROVAL_TOPIC, address_to_topic
from sweepsafe.chains import RpcError
from sweepsafe.config.chains import Chain
from sweepsafe.scanner import ScanError, Scanner, fetch_approval_logs, parse_approval_log
from sweepsafe.scanner import logs as logs_module
from sweepsafe.store import Store

CHAIN = Chain("testnet", 1, ("https://x.example",), "https://scan.example", None, reorg_depth=10)


@pytest.fixture
def store():
    with Store(":memory:") as s:
        yield s


# -- parse_approval_log ------------------------------------------------------------------------
def test_parse_valid_log():
    parsed = parse_approval_log(make_log(TOKEN_A, OWNER, SPENDER_1, 7, 123, 4, tx="0xAB"), OWNER)
    assert parsed is not None
    assert (parsed.token, parsed.spender, parsed.value) == (TOKEN_A, SPENDER_1, 7)
    assert (parsed.block_number, parsed.log_index, parsed.tx_hash) == (123, 4, "0xab")


def test_parse_ignores_erc721_removed_wrong_owner_and_garbage():
    good = make_log(TOKEN_A, OWNER, SPENDER_1, 1, 1)
    nft = {**good, "topics": [*good["topics"], "0x" + "00" * 32], "data": "0x"}
    assert parse_approval_log(nft, OWNER) is None
    assert parse_approval_log({**good, "removed": True}, OWNER) is None
    assert parse_approval_log(make_log(TOKEN_A, SPENDER_2, SPENDER_1, 1, 1), OWNER) is None
    assert parse_approval_log({**good, "data": "0x01"}, OWNER) is None
    assert parse_approval_log({**good, "data": None}, OWNER) is None
    assert (
        parse_approval_log({**good, "topics": [APPROVAL_TOPIC.replace("8c", "00")] * 3}, OWNER)
        is None
    )
    assert parse_approval_log({k: v for k, v in good.items() if k != "address"}, OWNER) is None
    assert parse_approval_log({**good, "blockNumber": "zz"}, OWNER) is None
    assert parse_approval_log({**good, "topics": "nope"}, OWNER) is None


# -- fetch_approval_logs -----------------------------------------------------------------------
def test_chunk_size_adapts_to_node_limit_without_gaps():
    node = FakeNode(max_range=1_000, logs=[make_log(TOKEN_A, OWNER, SPENDER_1, 1, 5_432)])
    chunks = list(fetch_approval_logs(node, OWNER, 0, 10_000, initial_chunk=8_000, min_chunk=100))
    assert chunks[0][0] == 0
    assert chunks[-1][1] == 10_000
    for (_, prev_end, _), (next_start, _, _) in zip(chunks, chunks[1:], strict=False):
        assert next_start == prev_end + 1  # contiguous: no block is ever skipped
    assert [lg.block_number for _, _, logs in chunks for lg in logs] == [5_432]
    assert all(end - start + 1 <= 1_000 for start, end, _ in chunks)


def test_chunk_grows_over_empty_ranges():
    node = FakeNode()
    list(fetch_approval_logs(node, OWNER, 0, 1_000_000, initial_chunk=100, max_chunk=100_000))
    assert len(node.log_requests) < 20


def test_chunk_shrinks_after_dense_result(monkeypatch):
    monkeypatch.setattr(logs_module, "DENSE_LOGS", 2)
    node = FakeNode(logs=[make_log(TOKEN_A, OWNER, SPENDER_1, i + 1, 10 + i, i) for i in range(3)])
    list(fetch_approval_logs(node, OWNER, 0, 1_000, initial_chunk=400, min_chunk=50))
    sizes = [end - start + 1 for start, end in node.log_requests]
    assert sizes[1] < sizes[0]


def test_scan_error_when_node_rejects_even_minimum_range():
    node = FakeNode(max_range=10)
    with pytest.raises(ScanError):
        list(fetch_approval_logs(node, OWNER, 0, 1_000, initial_chunk=100, min_chunk=50))


def test_non_range_errors_propagate():
    class Broken(FakeNode):
        def get_logs(self, *a, **k):
            raise RpcError(-32601, "method not found")

    with pytest.raises(RpcError):
        list(fetch_approval_logs(Broken(), OWNER, 0, 10))


def test_progress_callback_reports_to_the_end():
    seen = []
    list(fetch_approval_logs(FakeNode(), OWNER, 0, 500, progress=lambda d, t: seen.append((d, t))))
    assert seen and seen[-1] == (500, 500)


def test_owner_topic_filter_is_used():
    node = FakeNode(logs=[make_log(TOKEN_A, SPENDER_2, SPENDER_1, 1, 5)])
    assert [lg for _, _, logs in fetch_approval_logs(node, OWNER, 0, 10) for lg in logs] == []
    assert address_to_topic(OWNER) != address_to_topic(SPENDER_2)


# -- Scanner.sync_logs -------------------------------------------------------------------------
def test_sync_fresh_then_resume_only_rescans_tail(store):
    node = FakeNode(
        head=1_000,
        logs=[
            make_log(TOKEN_A, OWNER, SPENDER_1, 5, 100),
            make_log(TOKEN_A, OWNER, SPENDER_2, 5, 200),
        ],
    )
    scanner = Scanner(CHAIN, node, store)
    assert scanner.sync_logs(OWNER) == 1_000
    assert len(store.get_logs(1, OWNER)) == 2
    assert store.get_cursor(1, OWNER) == (0, 1_000)

    node.head = 1_500
    node.logs.append(make_log(TOKEN_B, OWNER, SPENDER_1, 9, 1_200))
    node.log_requests.clear()
    scanner.sync_logs(OWNER)
    assert node.log_requests[0][0] == 1_000 - CHAIN.reorg_depth + 1  # tail only, not genesis
    assert len(store.get_logs(1, OWNER)) == 3
    assert store.get_cursor(1, OWNER) == (0, 1_500)


def test_reorged_log_in_tail_is_discarded(store):
    stale = make_log(TOKEN_A, OWNER, SPENDER_1, 5, 995)
    node = FakeNode(head=1_000, logs=[stale])
    scanner = Scanner(CHAIN, node, store)
    scanner.sync_logs(OWNER)
    assert len(store.get_logs(1, OWNER)) == 1

    node.logs.clear()  # the block was reorged away
    node.head = 1_100
    scanner.sync_logs(OWNER)
    assert store.get_logs(1, OWNER) == []


def test_from_block_skips_history_and_warns(store):
    node = FakeNode(
        head=1_000,
        logs=[
            make_log(TOKEN_A, OWNER, SPENDER_1, 5, 100),
            make_log(TOKEN_A, OWNER, SPENDER_2, 5, 700),
        ],
    )
    scanner = Scanner(CHAIN, node, store)
    scanner.sync_logs(OWNER, from_block=500)
    assert [lg.block_number for lg in store.get_logs(1, OWNER)] == [700]
    assert any("History before block 500" in w for w in scanner.warnings)


def test_requesting_older_history_restarts_the_scan(store):
    node = FakeNode(head=1_000, logs=[make_log(TOKEN_A, OWNER, SPENDER_1, 5, 100)])
    Scanner(CHAIN, node, store).sync_logs(OWNER, from_block=500)
    assert store.get_logs(1, OWNER) == []

    fresh = Scanner(CHAIN, node, store)
    fresh.sync_logs(OWNER, from_block=0)
    assert [lg.block_number for lg in store.get_logs(1, OWNER)] == [100]
    assert fresh.warnings == []
    assert store.get_cursor(1, OWNER) == (0, 1_000)


def test_reset_rescans_everything(store):
    node = FakeNode(head=1_000, logs=[make_log(TOKEN_A, OWNER, SPENDER_1, 5, 100)])
    scanner = Scanner(CHAIN, node, store)
    scanner.sync_logs(OWNER)
    node.log_requests.clear()
    scanner.sync_logs(OWNER, reset=True)
    assert node.log_requests[0][0] == 0


def test_head_behind_cursor_is_a_noop(store):
    node = FakeNode(head=1_000)
    scanner = Scanner(CHAIN, node, store)
    scanner.sync_logs(OWNER)
    node.head = 500  # a lagging provider
    node.log_requests.clear()
    assert scanner.sync_logs(OWNER) == 1_000


# -- Scanner.active_approvals ------------------------------------------------------------------
def _scenario():
    nft = make_log(TOKEN_B, OWNER, SPENDER_2, 1, 55)
    nft["topics"].append("0x" + "00" * 32)
    nft["data"] = "0x"
    logs = [
        make_log(TOKEN_A, OWNER, SPENDER_1, 100, 10),
        make_log(TOKEN_A, OWNER, SPENDER_1, 0, 20),  # revoked
        make_log(TOKEN_A, OWNER, SPENDER_2, MAX_UINT, 30),
        make_log(TOKEN_B, OWNER, SPENDER_1, 50, 40),  # spent down to zero without an event
        make_log(TOKEN_B, OWNER, SPENDER_2, 5, 50),  # token reverts on allowance()
        nft,
    ]
    return FakeNode(
        head=1_000,
        logs=logs,
        allowances={
            (TOKEN_A, SPENDER_1): 0,
            (TOKEN_A, SPENDER_2): MAX_UINT,
            (TOKEN_B, SPENDER_1): 0,
        },
        tokens={TOKEN_A: ("USDC", 6)},
        timestamps={30: 1_700_000_000},
    )


def test_active_approvals_uses_live_allowance(store):
    node = _scenario()
    scanner = Scanner(CHAIN, node, store)
    scanner.sync_logs(OWNER)
    approvals = scanner.active_approvals(OWNER)
    assert [(a.token, a.spender) for a in approvals] == [(TOKEN_A, SPENDER_2)]
    only = approvals[0]
    assert only.allowance == MAX_UINT
    assert (only.token_symbol, only.token_decimals) == ("USDC", 6)
    assert only.timestamp == 1_700_000_000
    assert only.block_number == 30
    assert any("Could not read allowance" in w and TOKEN_B in w for w in scanner.warnings)


def test_token_metadata_and_timestamps_are_cached(store):
    node = _scenario()
    scanner = Scanner(CHAIN, node, store)
    scanner.sync_logs(OWNER)
    scanner.active_approvals(OWNER)
    first = len(node.calls)
    scanner.active_approvals(OWNER)
    meta_calls = [c for c in node.calls[first:] if c[1] != "0xdd62ed3e"]
    assert meta_calls == []


def test_missing_block_timestamp_degrades_gracefully(store):
    node = _scenario()
    node.timestamps.clear()
    scanner = Scanner(CHAIN, node, store)
    scanner.sync_logs(OWNER)
    approvals = scanner.active_approvals(OWNER)
    assert approvals[0].timestamp is None
    assert any("Could not read the date of block 30" in w for w in scanner.warnings)


def test_latest_event_wins_within_one_block(store):
    node = FakeNode(
        head=100,
        logs=[
            make_log(TOKEN_A, OWNER, SPENDER_1, 0, 10, log_index=5),
            make_log(TOKEN_A, OWNER, SPENDER_1, 9, 10, log_index=2),
        ],
        allowances={(TOKEN_A, SPENDER_1): 9},
    )
    scanner = Scanner(CHAIN, node, store)
    scanner.sync_logs(OWNER)
    assert scanner.active_approvals(OWNER) == []  # log_index 5 (zero) came last


def test_token_with_broken_metadata_still_listed(store):
    node = FakeNode(
        head=100,
        logs=[make_log(TOKEN_A, OWNER, SPENDER_1, 9, 10)],
        allowances={(TOKEN_A, SPENDER_1): 9},
        timestamps={10: 1},
    )
    scanner = Scanner(CHAIN, node, store)
    scanner.sync_logs(OWNER)
    (approval,) = scanner.active_approvals(OWNER)
    assert (approval.token_symbol, approval.token_decimals) == (None, None)
