"""Solana support: SPL token delegations (the Solana analogue of ERC-20 approvals).

Solana has no allowance events to replay. A token account holds at most one ``delegate`` and a
``delegatedAmount``, so a scan is a single read of the owner's token accounts. Revoking is the
SPL Token ``Revoke`` instruction, built here as an UNSIGNED transaction.
"""

from sweepsafe.solana.base58 import Base58Error, b58decode, b58encode, is_solana_address
from sweepsafe.solana.revoke import SolanaTx, build_revoke_message, build_revoke_tx
from sweepsafe.solana.scan import (
    SOLANA_EXPLORER,
    SOLANA_NAME,
    SOLANA_RPCS,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    scan_solana,
)

__all__ = [
    "SOLANA_EXPLORER",
    "SOLANA_NAME",
    "SOLANA_RPCS",
    "TOKEN_2022_PROGRAM",
    "TOKEN_PROGRAM",
    "Base58Error",
    "SolanaTx",
    "b58decode",
    "b58encode",
    "build_revoke_message",
    "build_revoke_tx",
    "is_solana_address",
    "scan_solana",
]
