"""Minimal base58 (Bitcoin alphabet) as used for Solana addresses and transactions."""

from __future__ import annotations

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


class Base58Error(ValueError):
    pass


def b58encode(data: bytes) -> str:
    zeros = len(data) - len(data.lstrip(b"\0"))
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = ALPHABET[rem] + out
    return "1" * zeros + out


def b58decode(text: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise Base58Error("empty base58 string")
    number = 0
    for char in text:
        if char not in _INDEX:
            raise Base58Error(f"invalid base58 character {char!r}")
        number = number * 58 + _INDEX[char]
    zeros = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * zeros + body


def is_solana_address(value: str) -> bool:
    """A Solana account address is 32 bytes, base58 encoded (32-44 characters)."""
    if not isinstance(value, str) or not 32 <= len(value) <= 44:
        return False
    try:
        return len(b58decode(value)) == 32
    except Base58Error:
        return False
