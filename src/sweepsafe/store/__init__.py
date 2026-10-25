"""SQLite cache (stdlib only). Everything here is a cache: deleting the file is always safe."""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from types import TracebackType

from sweepsafe.models import ApprovalLog, Verification

SCHEMA_VERSION = 1

VERIFIED_TTL = 30 * 86_400
UNVERIFIED_TTL = 86_400

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approval_logs (
    chain_id INTEGER NOT NULL,
    owner TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    log_index INTEGER NOT NULL,
    block_number INTEGER NOT NULL,
    token TEXT NOT NULL,
    spender TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (chain_id, owner, tx_hash, log_index)
);
CREATE INDEX IF NOT EXISTS idx_logs_block ON approval_logs (chain_id, owner, block_number);
CREATE TABLE IF NOT EXISTS scan_cursor (
    chain_id INTEGER NOT NULL,
    owner TEXT NOT NULL,
    first_block INTEGER NOT NULL,
    last_block INTEGER NOT NULL,
    PRIMARY KEY (chain_id, owner)
);
CREATE TABLE IF NOT EXISTS token_meta (
    chain_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    symbol TEXT,
    decimals INTEGER,
    PRIMARY KEY (chain_id, token)
);
CREATE TABLE IF NOT EXISTS block_ts (
    chain_id INTEGER NOT NULL,
    block_number INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY (chain_id, block_number)
);
CREATE TABLE IF NOT EXISTS verification_cache (
    chain_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    status TEXT NOT NULL,
    checked_at INTEGER NOT NULL,
    PRIMARY KEY (chain_id, address)
);
CREATE TABLE IF NOT EXISTS blocklist_cache (
    url TEXT PRIMARY KEY,
    fetched_at INTEGER NOT NULL,
    addresses TEXT NOT NULL
);
"""


class Store:
    """Thin typed wrapper around a SQLite connection. All SQL is parameterised."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path) if str(path) == ":memory:" else str(Path(path).expanduser())
        if self.path != ":memory:":
            parent = Path(self.path).parent
            created = not parent.exists()
            parent.mkdir(parents=True, exist_ok=True)
            if created:  # keep a directory we created private to the user
                with contextlib.suppress(OSError):
                    os.chmod(parent, 0o700)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    # -- lifecycle ---------------------------------------------------------------------------
    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- approval logs -----------------------------------------------------------------------
    def add_logs(self, chain_id: int, owner: str, logs: Iterable[ApprovalLog]) -> None:
        rows = [
            (chain_id, owner, lg.tx_hash, lg.log_index, lg.block_number, lg.token, lg.spender,
             str(lg.value))
            for lg in logs
        ]  # fmt: skip
        with self._conn:
            self._conn.executemany(
                "INSERT OR REPLACE INTO approval_logs "
                "(chain_id, owner, tx_hash, log_index, block_number, token, spender, value) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    def delete_logs_from(self, chain_id: int, owner: str, from_block: int) -> None:
        with self._conn:
            self._conn.execute(
                "DELETE FROM approval_logs WHERE chain_id = ? AND owner = ? AND block_number >= ?",
                (chain_id, owner, from_block),
            )

    def get_logs(self, chain_id: int, owner: str) -> list[ApprovalLog]:
        cur = self._conn.execute(
            "SELECT tx_hash, log_index, block_number, token, spender, value FROM approval_logs "
            "WHERE chain_id = ? AND owner = ? ORDER BY block_number, log_index",
            (chain_id, owner),
        )
        return [
            ApprovalLog(
                tx_hash=r["tx_hash"],
                log_index=r["log_index"],
                block_number=r["block_number"],
                token=r["token"],
                spender=r["spender"],
                value=int(r["value"]),
            )
            for r in cur
        ]

    # -- resume cursor -----------------------------------------------------------------------
    def get_cursor(self, chain_id: int, owner: str) -> tuple[int, int] | None:
        """(first_block, last_block) already covered for this wallet, or None."""
        row = self._conn.execute(
            "SELECT first_block, last_block FROM scan_cursor WHERE chain_id = ? AND owner = ?",
            (chain_id, owner),
        ).fetchone()
        return None if row is None else (int(row["first_block"]), int(row["last_block"]))

    def set_cursor(self, chain_id: int, owner: str, first_block: int, last_block: int) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO scan_cursor (chain_id, owner, first_block, last_block) "
                "VALUES (?, ?, ?, ?)",
                (chain_id, owner, first_block, last_block),
            )

    def reset_wallet(self, chain_id: int, owner: str) -> None:
        with self._conn:
            self._conn.execute(
                "DELETE FROM approval_logs WHERE chain_id = ? AND owner = ?", (chain_id, owner)
            )
            self._conn.execute(
                "DELETE FROM scan_cursor WHERE chain_id = ? AND owner = ?", (chain_id, owner)
            )

    # -- token metadata (immutable in practice) ----------------------------------------------
    def get_token_meta(self, chain_id: int, token: str) -> tuple[str | None, int | None] | None:
        row = self._conn.execute(
            "SELECT symbol, decimals FROM token_meta WHERE chain_id = ? AND token = ?",
            (chain_id, token),
        ).fetchone()
        return None if row is None else (row["symbol"], row["decimals"])

    def set_token_meta(
        self, chain_id: int, token: str, symbol: str | None, decimals: int | None
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO token_meta (chain_id, token, symbol, decimals) "
                "VALUES (?, ?, ?, ?)",
                (chain_id, token, symbol, decimals),
            )

    # -- block timestamps (immutable once final) ---------------------------------------------
    def get_block_ts(self, chain_id: int, block_number: int) -> int | None:
        row = self._conn.execute(
            "SELECT timestamp FROM block_ts WHERE chain_id = ? AND block_number = ?",
            (chain_id, block_number),
        ).fetchone()
        return None if row is None else int(row["timestamp"])

    def set_block_ts(self, chain_id: int, block_number: int, timestamp: int) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO block_ts (chain_id, block_number, timestamp) "
                "VALUES (?, ?, ?)",
                (chain_id, block_number, timestamp),
            )

    # -- contract verification cache ---------------------------------------------------------
    def get_verification(self, chain_id: int, address: str, now: int) -> Verification | None:
        row = self._conn.execute(
            "SELECT status, checked_at FROM verification_cache WHERE chain_id = ? AND address = ?",
            (chain_id, address),
        ).fetchone()
        if row is None:
            return None
        status = Verification(row["status"])
        ttl = VERIFIED_TTL if status is Verification.VERIFIED else UNVERIFIED_TTL
        if now - int(row["checked_at"]) > ttl:
            return None
        return status

    def set_verification(self, chain_id: int, address: str, status: Verification, now: int) -> None:
        if status is Verification.UNKNOWN:
            return  # never cache "we could not tell"
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO verification_cache "
                "(chain_id, address, status, checked_at) VALUES (?, ?, ?, ?)",
                (chain_id, address, status.value, now),
            )

    # -- blocklist cache ---------------------------------------------------------------------
    def get_blocklist_cache(self, url: str) -> tuple[int, set[str]] | None:
        row = self._conn.execute(
            "SELECT fetched_at, addresses FROM blocklist_cache WHERE url = ?", (url,)
        ).fetchone()
        if row is None:
            return None
        addresses = {a for a in row["addresses"].split("\n") if a}
        return int(row["fetched_at"]), addresses

    def set_blocklist_cache(self, url: str, fetched_at: int, addresses: set[str]) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO blocklist_cache (url, fetched_at, addresses) "
                "VALUES (?, ?, ?)",
                (url, fetched_at, "\n".join(sorted(addresses))),
            )
