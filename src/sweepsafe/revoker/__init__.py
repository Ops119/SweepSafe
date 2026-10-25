"""Build UNSIGNED ``approve(spender, 0)`` transactions. This module never touches private keys."""

from __future__ import annotations

from collections.abc import Iterable

from sweepsafe.abi import encode_approve, normalize_address
from sweepsafe.config.chains import Chain
from sweepsafe.explain.format import short_address
from sweepsafe.models import Approval, ScoredApproval, UnsignedTx


def build_revoke_tx(chain: Chain, approval: Approval) -> UnsignedTx:
    """Transaction that sets the spender's allowance on ``approval.token`` back to zero.

    The transaction must be sent *from the owner's account* to affect the owner's allowance;
    front-ends are expected to verify the connected account equals ``approval.owner``.
    """
    if approval.chain != chain.name:
        raise ValueError(f"approval is for {approval.chain!r}, not {chain.name!r}")
    token = normalize_address(approval.token)
    spender = normalize_address(approval.spender)
    label = approval.token_symbol or short_address(token)
    return UnsignedTx(
        chain_id=chain.chain_id,
        to=token,
        data=encode_approve(spender, 0),
        description=f"Revoke {label} allowance for {short_address(spender)} on {chain.name}",
    )


def select_for_revoke(
    approvals: Iterable[ScoredApproval],
    *,
    min_score: int = 0,
    token: str | None = None,
    spender: str | None = None,
) -> list[ScoredApproval]:
    """Filter scored approvals by minimum risk score and/or exact token/spender address."""
    token_n = normalize_address(token) if token else None
    spender_n = normalize_address(spender) if spender else None
    selected = []
    for item in approvals:
        if item.risk.score < min_score:
            continue
        if token_n and item.approval.token != token_n:
            continue
        if spender_n and item.approval.spender != spender_n:
            continue
        selected.append(item)
    return selected


def build_revoke_txs(chain: Chain, approvals: Iterable[ScoredApproval]) -> list[UnsignedTx]:
    return [build_revoke_tx(chain, item.approval) for item in approvals]
