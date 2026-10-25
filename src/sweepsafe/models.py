"""Typed data models shared across SweepSafe modules."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_serializer


class Verification(StrEnum):
    """Whether a spender contract has publicly verified source code."""

    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    UNKNOWN = "unknown"


class ApprovalLog(BaseModel):
    """One raw ERC-20 ``Approval`` event emitted for an owner."""

    model_config = ConfigDict(frozen=True)

    token: str
    spender: str
    value: int
    block_number: int
    log_index: int
    tx_hash: str

    @property
    def order_key(self) -> tuple[int, int]:
        return (self.block_number, self.log_index)


class Approval(BaseModel):
    """A currently-active approval, enriched with context needed for risk scoring."""

    chain: str
    owner: str
    token: str
    spender: str
    allowance: int  # live on-chain value (uint256)
    block_number: int
    tx_hash: str
    timestamp: int | None = None
    token_symbol: str | None = None
    token_decimals: int | None = None
    spender_is_contract: bool | None = None
    verification: Verification = Verification.UNKNOWN
    blocklisted: bool = False
    # Solana only: the SPL token account holding the delegation, and its token program.
    token_account: str | None = None
    token_program: str | None = None

    @field_serializer("allowance")
    def _allowance_as_string(self, value: int) -> str:
        # uint256 does not fit in a JSON number for JavaScript consumers.
        return str(value)


class RiskFinding(BaseModel):
    rule_id: str
    weight: int
    message: str


class RiskResult(BaseModel):
    score: int = Field(ge=0, le=100)
    level: str
    findings: list[RiskFinding] = Field(default_factory=list)


class ScoredApproval(BaseModel):
    approval: Approval
    risk: RiskResult
    explanation: str


class ScanResult(BaseModel):
    chain: str
    chain_id: int
    owner: str
    scanned_to_block: int
    generated_at: int  # unix seconds
    approvals: list[ScoredApproval] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class UnsignedTx(BaseModel):
    """A transaction for the user to review and sign in their own wallet. Never signed here."""

    chain_id: int
    to: str
    data: str
    value: str = "0x0"
    description: str = ""

    def as_wallet_request(self) -> dict[str, str]:
        """Shape accepted by ``eth_sendTransaction`` (``from`` is added by the wallet)."""
        return {
            "to": self.to,
            "data": self.data,
            "value": self.value,
            "chainId": hex(self.chain_id),
        }
