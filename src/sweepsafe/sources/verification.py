"""Contract-verification lookups against free, keyless public APIs (Sourcify, Blockscout)."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Protocol

from sweepsafe.abi import normalize_address
from sweepsafe.chains.transport import Transport, TransportError
from sweepsafe.config.chains import Chain
from sweepsafe.models import Verification
from sweepsafe.store import Store

SOURCIFY_BASE = "https://sourcify.dev/server/v2/contract"


class VerificationProvider(Protocol):
    name: str

    def check(self, chain: Chain, address: str) -> Verification: ...


class SourcifyProvider:
    name = "sourcify"

    def __init__(self, transport: Transport, *, timeout: float = 20.0) -> None:
        self.transport = transport
        self.timeout = timeout

    def check(self, chain: Chain, address: str) -> Verification:
        url = f"{SOURCIFY_BASE}/{chain.chain_id}/{normalize_address(address)}"
        try:
            body = self.transport.get_json(url, timeout=self.timeout)
        except TransportError as exc:
            return Verification.UNVERIFIED if exc.status == 404 else Verification.UNKNOWN
        return Verification.VERIFIED if isinstance(body, dict) and body else Verification.UNKNOWN


class BlockscoutProvider:
    name = "blockscout"

    def __init__(self, transport: Transport, *, timeout: float = 20.0) -> None:
        self.transport = transport
        self.timeout = timeout

    def check(self, chain: Chain, address: str) -> Verification:
        if not chain.blockscout:
            return Verification.UNKNOWN
        url = f"{chain.blockscout}/api/v2/smart-contracts/{normalize_address(address)}"
        try:
            body = self.transport.get_json(url, timeout=self.timeout)
        except TransportError as exc:
            return Verification.UNVERIFIED if exc.status == 404 else Verification.UNKNOWN
        if not isinstance(body, dict):
            return Verification.UNKNOWN
        return Verification.VERIFIED if body.get("is_verified") is True else Verification.UNVERIFIED


class CompositeVerifier:
    """Ask each provider in turn.

    * ``verified`` anywhere wins (a contract verified on one service is verified).
    * ``unverified`` only if at least one provider answered definitively and none said verified.
    * ``unknown`` when nobody could be reached, so a network blip never creates a false alarm.

    Results are cached in SQLite (verified for 30 days, unverified for 1 day, unknown never).
    """

    def __init__(
        self,
        providers: Sequence[VerificationProvider],
        store: Store | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.providers = list(providers)
        self.store = store
        self._now = now

    def check(self, chain: Chain, address: str) -> Verification:
        address = normalize_address(address)
        now = int(self._now())
        if self.store is not None:
            cached = self.store.get_verification(chain.chain_id, address, now)
            if cached is not None:
                return cached

        answers = []
        for provider in self.providers:
            result = provider.check(chain, address)
            if result is Verification.VERIFIED:
                answers = [result]
                break
            answers.append(result)

        if Verification.VERIFIED in answers:
            final = Verification.VERIFIED
        elif Verification.UNVERIFIED in answers:
            final = Verification.UNVERIFIED
        else:
            final = Verification.UNKNOWN

        if self.store is not None:
            self.store.set_verification(chain.chain_id, address, final, now)
        return final


def default_verifier(
    transport: Transport, store: Store | None, *, timeout: float = 20.0
) -> CompositeVerifier:
    return CompositeVerifier(
        [
            SourcifyProvider(transport, timeout=timeout),
            BlockscoutProvider(transport, timeout=timeout),
        ],
        store,
    )
