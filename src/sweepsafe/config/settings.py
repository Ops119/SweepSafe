"""Environment-driven settings. Nothing here requires an API key."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

# MetaMask's eth-phishing-detect list is domain-based, so it cannot match spender addresses.
# These community lists are address-based. Both are plain JSON on GitHub; override via env.
DEFAULT_BLOCKLIST_URLS = (
    "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json",
    "https://raw.githubusercontent.com/MyCryptoHQ/ethereum-lists/master/src/addresses/addresses-darklist.json",
)

DEFAULT_PAGES_URL = "https://ops119.github.io/SweepSafe"


@dataclass(frozen=True)
class Settings:
    db_path: Path
    request_interval: float = 0.15  # seconds between RPC requests (be gentle on public nodes)
    timeout: float = 20.0
    retries: int = 3
    backoff: float = 0.75
    blocklist_urls: tuple[str, ...] = DEFAULT_BLOCKLIST_URLS
    blocklist_ttl: int = 86_400
    pages_url: str = DEFAULT_PAGES_URL

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        db = env.get("SWEEPSAFE_DB") or str(Path.home() / ".sweepsafe" / "cache.db")
        urls = tuple(
            u.strip() for u in env.get("SWEEPSAFE_BLOCKLIST_URLS", "").split(",") if u.strip()
        )
        return cls(
            db_path=Path(db),
            request_interval=float(env.get("SWEEPSAFE_REQUEST_INTERVAL", cls.request_interval)),
            timeout=float(env.get("SWEEPSAFE_TIMEOUT", cls.timeout)),
            retries=int(env.get("SWEEPSAFE_RETRIES", cls.retries)),
            backoff=float(env.get("SWEEPSAFE_BACKOFF", cls.backoff)),
            blocklist_urls=urls or DEFAULT_BLOCKLIST_URLS,
            pages_url=env.get("SWEEPSAFE_PAGES_URL", DEFAULT_PAGES_URL).rstrip("/"),
        )

    def rpc_overrides(
        self, chain_name: str, env: Mapping[str, str] | None = None
    ) -> tuple[str, ...]:
        """RPC URLs from ``SWEEPSAFE_RPC_<CHAIN>`` (comma separated), if set."""
        env = os.environ if env is None else env
        raw = env.get(f"SWEEPSAFE_RPC_{chain_name.upper()}", "")
        return tuple(u.strip() for u in raw.split(",") if u.strip())
