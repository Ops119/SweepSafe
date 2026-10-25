"""Build an UNSIGNED SPL Token ``Revoke`` transaction. Never touches private keys."""

from __future__ import annotations

import base64

from pydantic import BaseModel

from sweepsafe.explain.format import short_address
from sweepsafe.models import Approval
from sweepsafe.solana.base58 import b58decode, b58encode

REVOKE_INSTRUCTION = b"\x05"  # SPL Token (and Token-2022) instruction index 5


class SolanaTx(BaseModel):
    """Unsigned transaction: the user's wallet signs it. ``signatures`` are zero placeholders."""

    owner: str
    token_account: str
    description: str
    transaction_base64: str
    transaction_base58: str


def _compact(n: int) -> bytes:
    """Solana compact-u16 length prefix."""
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_revoke_message(owner: str, token_account: str, program: str, blockhash: str) -> bytes:
    """Legacy message: fee payer = owner; one Revoke instruction on ``token_account``."""
    keys = [b58decode(owner), b58decode(token_account), b58decode(program)]
    if any(len(k) != 32 for k in keys):
        raise ValueError("addresses must be 32 bytes")
    recent = b58decode(blockhash)
    if len(recent) != 32:
        raise ValueError("blockhash must be 32 bytes")
    header = bytes([1, 0, 1])  # 1 signer; 0 readonly signers; 1 readonly unsigned (program)
    instruction = (
        bytes([2])  # program id index
        + _compact(2)
        + bytes([1, 0])  # accounts: token account (writable), owner (signer)
        + _compact(len(REVOKE_INSTRUCTION))
        + REVOKE_INSTRUCTION
    )
    return header + _compact(3) + b"".join(keys) + recent + _compact(1) + instruction


def build_revoke_tx(approval: Approval, blockhash: str) -> SolanaTx:
    if approval.chain != "solana" or not approval.token_account or not approval.token_program:
        raise ValueError("not a Solana delegation")
    message = build_revoke_message(
        approval.owner, approval.token_account, approval.token_program, blockhash
    )
    raw = _compact(1) + b"\0" * 64 + message  # one empty signature slot, then the message
    label = approval.token_symbol or short_address(approval.token)
    return SolanaTx(
        owner=approval.owner,
        token_account=approval.token_account,
        description=(
            f"Revoke delegate {short_address(approval.spender)} on {label} token account "
            f"{short_address(approval.token_account)}"
        ),
        transaction_base64=base64.b64encode(raw).decode(),
        transaction_base58=b58encode(raw),
    )
