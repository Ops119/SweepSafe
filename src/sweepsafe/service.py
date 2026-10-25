"""Orchestration: scan -> enrich -> score -> explain. Pure wiring, easy to fake in tests."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Protocol

from sweepsafe.chains.rpc import ChainReader, RpcClient, RpcError, RpcUnavailableError
from sweepsafe.chains.transport import Transport, TransportError, UrllibTransport
from sweepsafe.config.chains import Chain, get_chain
from sweepsafe.config.settings import Settings
from sweepsafe.explain import explain_approval
from sweepsafe.models import Approval, ScanResult, ScoredApproval, Verification
from sweepsafe.risk import RiskEngine, RiskInput, age_in_days
from sweepsafe.scanner import Scanner
from sweepsafe.sources.blocklist import Blocklist, BlocklistManager
from sweepsafe.sources.verification import default_verifier
from sweepsafe.store import Store

_DELEGATION_PREFIX = "0xef0100"  # EIP-7702: an EOA that delegates to code is still a wallet


class Verifier(Protocol):
    def check(self, chain: Chain, address: str) -> Verification: ...


def is_contract_code(code: str) -> bool:
    """True for deployed contract code; False for plain wallets (incl. EIP-7702 delegated EOAs)."""
    lowered = code.lower()
    if lowered in ("", "0x", "0x0"):
        return False
    return not (lowered.startswith(_DELEGATION_PREFIX) and len(lowered) == 2 + 23 * 2)


def classify_spender(reader: ChainReader, address: str) -> bool | None:
    """True = contract, False = wallet, None = could not tell."""
    try:
        return is_contract_code(reader.get_code(address))
    except (RpcError, RpcUnavailableError, TransportError):
        return None


def scan_wallet(
    owner: str,
    chain: Chain,
    *,
    reader: ChainReader,
    store: Store,
    verifier: Verifier,
    blocklist: Blocklist | None = None,
    engine: RiskEngine | None = None,
    from_block: int | None = None,
    reset: bool = False,
    progress: Callable[[int, int], None] | None = None,
    now: Callable[[], float] = time.time,
) -> ScanResult:
    blocklist = blocklist or Blocklist()
    engine = engine or RiskEngine()
    scanner = Scanner(chain, reader, store, progress=progress, now=now)
    scanned_to = scanner.sync_logs(owner, from_block=from_block, reset=reset)
    approvals = scanner.active_approvals(owner)

    warnings = list(scanner.warnings) + blocklist.warnings
    kinds: dict[str, bool | None] = {}
    now_s = int(now())
    scored: list[ScoredApproval] = []

    for approval in approvals:
        _enrich(approval, chain, reader, verifier, blocklist, kinds, warnings)
        risk = engine.evaluate(
            RiskInput(
                allowance=approval.allowance,
                spender_is_contract=approval.spender_is_contract,
                verification=approval.verification,
                blocklisted=approval.blocklisted,
                age_days=age_in_days(approval.timestamp, now_s),
            )
        )
        scored.append(
            ScoredApproval(
                approval=approval,
                risk=risk,
                explanation=explain_approval(approval, risk, engine.rules),
            )
        )

    scored.sort(key=lambda s: (-s.risk.score, s.approval.token, s.approval.spender))
    return ScanResult(
        chain=chain.name,
        chain_id=chain.chain_id,
        owner=owner.lower(),
        scanned_to_block=scanned_to,
        generated_at=now_s,
        approvals=scored,
        warnings=warnings,
    )


def _enrich(
    approval: Approval,
    chain: Chain,
    reader: ChainReader,
    verifier: Verifier,
    blocklist: Blocklist,
    kinds: dict[str, bool | None],
    warnings: list[str],
) -> None:
    spender = approval.spender
    if spender not in kinds:
        kinds[spender] = classify_spender(reader, spender)
        if kinds[spender] is None:
            warnings.append(f"Could not tell whether spender {spender} is a contract.")
    approval.spender_is_contract = kinds[spender]
    approval.blocklisted = spender in blocklist
    if approval.spender_is_contract:
        approval.verification = verifier.check(chain, spender)
    else:
        approval.verification = Verification.UNKNOWN


@dataclass
class Dependencies:
    """Real-world wiring (public RPCs, SQLite cache, free APIs). Use as a context manager."""

    chain: Chain
    reader: RpcClient
    store: Store
    verifier: Verifier
    blocklist: Blocklist

    def __enter__(self) -> Dependencies:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.store.close()


def open_dependencies(
    chain_name: str,
    settings: Settings,
    *,
    rpc_urls: tuple[str, ...] = (),
    transport: Transport | None = None,
    refresh_blocklist: bool = True,
) -> Dependencies:
    chain = get_chain(chain_name, rpc_urls or settings.rpc_overrides(chain_name))
    transport = transport or UrllibTransport()
    store = Store(settings.db_path)
    reader = RpcClient(
        chain.rpcs,
        transport,
        expected_chain_id=chain.chain_id,
        retries=settings.retries,
        backoff=settings.backoff,
        min_interval=settings.request_interval,
        timeout=settings.timeout,
    )
    verifier = default_verifier(transport, store, timeout=settings.timeout)
    blocklist = Blocklist()
    if refresh_blocklist:
        blocklist = BlocklistManager(
            store,
            transport,
            settings.blocklist_urls,
            ttl=settings.blocklist_ttl,
            timeout=settings.timeout,
        ).load()
    return Dependencies(chain, reader, store, verifier, blocklist)
