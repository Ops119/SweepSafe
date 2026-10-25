"""Scan a Solana wallet for active SPL token delegations and score them."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Protocol

from sweepsafe.chains.rpc import RpcError, RpcUnavailableError
from sweepsafe.chains.transport import TransportError
from sweepsafe.explain import explain_approval
from sweepsafe.explain.format import MAX_DECIMALS
from sweepsafe.models import Approval, ScanResult, ScoredApproval, Verification
from sweepsafe.risk import RiskEngine, RiskInput
from sweepsafe.solana.base58 import is_solana_address

SOLANA_NAME = "solana"
SOLANA_CLUSTER_ID = 101  # label only; Solana has no chain id
SOLANA_EXPLORER = "https://solscan.io"
SOLANA_RPCS = (
    "https://solana-rpc.publicnode.com",
    "https://api.mainnet-beta.solana.com",
)
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
SYSTEM_PROGRAM = "11111111111111111111111111111111"
_U64_HALF = 1 << 63  # a delegated amount this large is effectively "unlimited"
_MAX_UINT256 = (1 << 256) - 1


class SolanaReader(Protocol):
    def call(self, method: str, params: list[Any] | None = None) -> Any: ...


def _parse_account(entry: Any, owner: str, program: str) -> Approval | None:
    """One token account -> an Approval when it has an active delegate, else None."""
    try:
        info = entry["account"]["data"]["parsed"]["info"]
        delegate = info.get("delegate")
        if not delegate or not is_solana_address(delegate):
            return None
        raw_amount = info["delegatedAmount"]["amount"]
        # Strict digits only, so Python and the JS viewer accept exactly the same inputs
        # (int() would also take "1_000", " 5 " and "+5").
        if not (isinstance(raw_amount, str) and raw_amount.isascii() and raw_amount.isdigit()):
            return None
        delegated = int(raw_amount)
        if delegated <= 0:
            return None
        mint = info["mint"]
        pubkey = entry["pubkey"]
        if not (is_solana_address(mint) and is_solana_address(pubkey)):
            return None
        decimals = info["delegatedAmount"].get("decimals")
        if not isinstance(decimals, int) or not 0 <= decimals <= MAX_DECIMALS:
            decimals = None
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    return Approval(
        chain=SOLANA_NAME,
        owner=owner,
        token=mint,
        spender=delegate,
        # Solana amounts are u64; map "effectively unlimited" onto the shared unlimited rule.
        allowance=_MAX_UINT256 if delegated >= _U64_HALF else delegated,
        block_number=0,
        tx_hash="",
        token_decimals=decimals,
        token_account=pubkey,
        token_program=program,
    )


def _is_program(reader: SolanaReader, address: str) -> bool | None:
    """True = on-chain program, False = ordinary wallet / empty account, None = unknown."""
    try:
        value = reader.call(
            "getAccountInfo",
            [address, {"encoding": "base64", "dataSlice": {"offset": 0, "length": 0}}],
        )
    except (RpcError, RpcUnavailableError, TransportError):
        return None
    account = value.get("value") if isinstance(value, dict) else None
    if account is None:
        return False
    if account.get("executable") is True:
        return True
    return False if account.get("owner") == SYSTEM_PROGRAM else None


def scan_solana(
    owner: str,
    *,
    reader: SolanaReader,
    engine: RiskEngine | None = None,
    now: Callable[[], float] = time.time,
) -> ScanResult:
    if not is_solana_address(owner):
        raise ValueError("not a valid Solana address")
    engine = engine or RiskEngine()
    warnings = [
        "Solana: no public scam-address list is configured, so blocklist checks are skipped.",
        "Solana: program source verification is not available, so programs show as unknown.",
    ]
    approvals: list[Approval] = []
    for program in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        result = reader.call(
            "getTokenAccountsByOwner", [owner, {"programId": program}, {"encoding": "jsonParsed"}]
        )
        entries = result.get("value") if isinstance(result, dict) else None
        if not isinstance(entries, list):
            raise TransportError("getTokenAccountsByOwner returned an unexpected shape")
        for entry in entries:
            approval = _parse_account(entry, owner, program)
            if approval is not None:
                approvals.append(approval)

    slot = reader.call("getSlot", [])
    kinds: dict[str, bool | None] = {}
    scored: list[ScoredApproval] = []
    for approval in approvals:
        if approval.spender not in kinds:
            kinds[approval.spender] = _is_program(reader, approval.spender)
            if kinds[approval.spender] is None:
                warnings.append(f"Could not tell what kind of account {approval.spender} is.")
        approval.spender_is_contract = kinds[approval.spender]
        approval.verification = Verification.UNKNOWN
        risk = engine.evaluate(
            RiskInput(
                allowance=approval.allowance,
                spender_is_contract=approval.spender_is_contract,
                verification=approval.verification,
                blocklisted=False,
                age_days=None,
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
        chain=SOLANA_NAME,
        chain_id=SOLANA_CLUSTER_ID,
        owner=owner,
        scanned_to_block=int(slot) if isinstance(slot, int) else 0,
        generated_at=int(now()),
        approvals=scored,
        warnings=warnings,
    )
