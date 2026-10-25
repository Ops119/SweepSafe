"""Community scam-address blocklists, cached locally and refreshed daily."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from sweepsafe.abi import is_address
from sweepsafe.chains.transport import Transport, TransportError
from sweepsafe.store import Store

MAX_ADDRESSES = 1_000_000
_SKIP_KEYS = ("white", "allow", "safe", "trusted")


def _walk(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        if is_address(node):
            yield node.lower()
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)
    elif isinstance(node, dict):
        for key, value in node.items():
            # Never let an allow/safe-list leak into the blocklist.
            if any(marker in str(key).lower() for marker in _SKIP_KEYS):
                continue
            yield from _walk(value)


def parse_address_list(data: Any) -> set[str]:
    """Extract addresses from the shapes the public lists use (flat list, list of objects, dict)."""
    found: set[str] = set()
    for address in _walk(data):
        found.add(address)
        if len(found) >= MAX_ADDRESSES:
            break
    return found


@dataclass
class Blocklist:
    addresses: frozenset[str] = frozenset()
    sources_ok: int = 0
    stale_sources: list[str] = field(default_factory=list)
    failed_sources: list[str] = field(default_factory=list)

    def __contains__(self, address: str) -> bool:
        return address.lower() in self.addresses

    @property
    def warnings(self) -> list[str]:
        out = [f"Blocklist source unavailable (no cached copy): {u}" for u in self.failed_sources]
        out += [
            f"Blocklist source could not be refreshed, using cached copy: {u}"
            for u in self.stale_sources
        ]
        return out


class BlocklistManager:
    def __init__(
        self,
        store: Store,
        transport: Transport,
        urls: Sequence[str],
        *,
        ttl: int = 86_400,
        timeout: float = 20.0,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.transport = transport
        self.urls = list(urls)
        self.ttl = ttl
        self.timeout = timeout
        self._now = now

    def load(self) -> Blocklist:
        result = Blocklist()
        merged: set[str] = set()
        now = int(self._now())
        for url in self.urls:
            cached = self.store.get_blocklist_cache(url)
            if cached is not None and now - cached[0] <= self.ttl:
                merged |= cached[1]
                result.sources_ok += 1
                continue
            try:
                addresses = parse_address_list(self.transport.get_json(url, timeout=self.timeout))
            except TransportError:
                if cached is not None:
                    merged |= cached[1]
                    result.stale_sources.append(url)
                else:
                    result.failed_sources.append(url)
                continue
            self.store.set_blocklist_cache(url, now, addresses)
            merged |= addresses
            result.sources_ok += 1
        result.addresses = frozenset(merged)
        return result
