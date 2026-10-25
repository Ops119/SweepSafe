import os
import stat

from sweepsafe.models import ApprovalLog, Verification
from sweepsafe.store import UNVERIFIED_TTL, VERIFIED_TTL, Store

OWNER = "0x" + "11" * 20
TOKEN = "0x" + "aa" * 20
SPENDER = "0x" + "c1" * 20


def log(block, index=0, value=1, tx="0x01"):
    return ApprovalLog(
        token=TOKEN, spender=SPENDER, value=value, block_number=block, log_index=index, tx_hash=tx
    )


def test_logs_round_trip_with_uint256_values():
    big = (1 << 256) - 1
    with Store() as store:
        store.add_logs(1, OWNER, [log(5, value=big, tx="0xa"), log(3, tx="0xb")])
        stored = store.get_logs(1, OWNER)
        assert [lg.block_number for lg in stored] == [3, 5]  # ordered
        assert stored[1].value == big  # exact, not truncated to int64
        assert store.get_logs(2, OWNER) == []  # scoped per chain


def test_add_logs_is_idempotent_and_delete_from():
    with Store() as store:
        store.add_logs(1, OWNER, [log(5, tx="0xa")])
        store.add_logs(1, OWNER, [log(5, tx="0xa")])
        assert len(store.get_logs(1, OWNER)) == 1
        store.add_logs(1, OWNER, [log(10, tx="0xb"), log(11, tx="0xc")])
        store.delete_logs_from(1, OWNER, 10)
        assert [lg.block_number for lg in store.get_logs(1, OWNER)] == [5]


def test_cursor_and_reset_wallet():
    with Store() as store:
        assert store.get_cursor(1, OWNER) is None
        store.set_cursor(1, OWNER, 10, 500)
        assert store.get_cursor(1, OWNER) == (10, 500)
        store.add_logs(1, OWNER, [log(5)])
        store.reset_wallet(1, OWNER)
        assert store.get_cursor(1, OWNER) is None and store.get_logs(1, OWNER) == []


def test_token_meta_allows_nulls_and_distinguishes_missing():
    with Store() as store:
        assert store.get_token_meta(1, TOKEN) is None
        store.set_token_meta(1, TOKEN, None, None)
        assert store.get_token_meta(1, TOKEN) == (None, None)
        store.set_token_meta(1, TOKEN, "USDC", 6)
        assert store.get_token_meta(1, TOKEN) == ("USDC", 6)


def test_block_timestamps():
    with Store() as store:
        assert store.get_block_ts(1, 7) is None
        store.set_block_ts(1, 7, 1_700_000_000)
        assert store.get_block_ts(1, 7) == 1_700_000_000


def test_verification_ttl_differs_by_status():
    with Store() as store:
        store.set_verification(1, SPENDER, Verification.VERIFIED, 1_000)
        assert store.get_verification(1, SPENDER, 1_000 + VERIFIED_TTL) is Verification.VERIFIED
        assert store.get_verification(1, SPENDER, 1_001 + VERIFIED_TTL) is None
        store.set_verification(1, SPENDER, Verification.UNVERIFIED, 1_000)
        assert store.get_verification(1, SPENDER, 1_000 + UNVERIFIED_TTL) is Verification.UNVERIFIED
        assert store.get_verification(1, SPENDER, 1_001 + UNVERIFIED_TTL) is None


def test_unknown_verification_is_never_stored():
    with Store() as store:
        store.set_verification(1, SPENDER, Verification.UNKNOWN, 1_000)
        assert store.get_verification(1, SPENDER, 1_000) is None


def test_blocklist_cache_round_trip():
    with Store() as store:
        assert store.get_blocklist_cache("https://x") is None
        store.set_blocklist_cache("https://x", 99, {TOKEN, SPENDER})
        assert store.get_blocklist_cache("https://x") == (99, {TOKEN, SPENDER})
        store.set_blocklist_cache("https://x", 100, set())
        assert store.get_blocklist_cache("https://x") == (100, set())


def test_file_database_persists_and_creates_private_directory(tmp_path):
    path = tmp_path / "nested" / "cache.db"
    with Store(path) as store:
        store.set_cursor(1, OWNER, 0, 42)
    with Store(path) as store:
        assert store.get_cursor(1, OWNER) == (0, 42)
    if os.name == "posix":
        mode = stat.S_IMODE(os.stat(path.parent).st_mode)
        assert mode == 0o700


def test_sql_injection_attempts_are_inert():
    nasty = "0x'; DROP TABLE approval_logs; --"
    with Store() as store:
        store.set_token_meta(1, nasty, "X", 1)
        assert store.get_token_meta(1, nasty) == ("X", 1)
        store.add_logs(1, OWNER, [log(1)])
        assert len(store.get_logs(1, OWNER)) == 1
