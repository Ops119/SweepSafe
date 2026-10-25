"""Minimal, dependency-free ABI helpers for the handful of ERC-20 calls SweepSafe needs."""

from __future__ import annotations

import re

# keccak256("Approval(address,address,uint256)"). ERC-20 logs carry 3 topics; ERC-721 logs that
# share this signature carry 4 (tokenId is indexed), which is how we tell them apart.
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

SELECTOR_APPROVE = "0x095ea7b3"  # approve(address,uint256)
SELECTOR_ALLOWANCE = "0xdd62ed3e"  # allowance(address,address)
SELECTOR_SYMBOL = "0x95d89b41"  # symbol()
SELECTOR_DECIMALS = "0x313ce567"  # decimals()

MAX_UINT256 = (1 << 256) - 1
ZERO_ADDRESS = "0x" + "00" * 20

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")


class AbiError(ValueError):
    """Raised when data cannot be encoded or decoded safely."""


def is_address(value: object) -> bool:
    return isinstance(value, str) and bool(_ADDRESS_RE.match(value))


def normalize_address(value: str) -> str:
    """Lower-case canonical form. Raises AbiError for anything that is not a 20-byte hex string."""
    if not is_address(value):
        raise AbiError(f"invalid address: {value!r}")
    return value.lower()


def address_to_topic(address: str) -> str:
    """Left-pad an address to a 32-byte topic."""
    return "0x" + "0" * 24 + normalize_address(address)[2:]


def topic_to_address(topic: str) -> str:
    if not isinstance(topic, str) or not _HEX_RE.match(topic) or len(topic) != 66:
        raise AbiError(f"invalid topic: {topic!r}")
    return "0x" + topic[-40:].lower()


def encode_uint256(value: int) -> str:
    if not 0 <= value <= MAX_UINT256:
        raise AbiError("uint256 out of range")
    return f"{value:064x}"


def encode_allowance_call(owner: str, spender: str) -> str:
    return (
        SELECTOR_ALLOWANCE
        + normalize_address(owner)[2:].rjust(64, "0")
        + normalize_address(spender)[2:].rjust(64, "0")
    )


def encode_approve(spender: str, amount: int) -> str:
    return SELECTOR_APPROVE + normalize_address(spender)[2:].rjust(64, "0") + encode_uint256(amount)


def decode_uint256(data: str) -> int:
    """Decode a single uint256 return value (rejects empty / truncated / oversize data)."""
    if not isinstance(data, str) or not _HEX_RE.match(data):
        raise AbiError("not hex data")
    body = data[2:]
    if len(body) != 64:
        raise AbiError(f"expected a single 32-byte word, got {len(body) // 2} bytes")
    return int(body, 16)


def decode_hex_int(value: str) -> int:
    """Decode a JSON-RPC quantity such as '0x1b4'."""
    if not isinstance(value, str) or not _HEX_RE.match(value) or len(value) < 3:
        raise AbiError(f"invalid quantity: {value!r}")
    return int(value, 16)


def sanitize_text(text: str, limit: int = 32) -> str:
    """Strip control characters and cap the length of attacker-controlled strings."""
    cleaned = "".join(ch for ch in text if ch.isprintable())
    return cleaned.strip()[:limit]


def decode_string(data: str) -> str | None:
    """Decode a token ``symbol()`` result: either an ABI string or a legacy bytes32.

    Token metadata is attacker-controlled, so the result is sanitised and length-capped.
    Returns None when the data cannot be interpreted.
    """
    if not isinstance(data, str) or not _HEX_RE.match(data):
        return None
    body = data[2:]
    if len(body) % 2:
        return None
    raw = bytes.fromhex(body)
    try:
        if len(raw) == 32:  # legacy bytes32 (e.g. MKR)
            text = raw.rstrip(b"\x00").decode("utf-8", errors="replace")
        elif len(raw) >= 64:
            offset = int.from_bytes(raw[:32], "big")
            if offset + 32 > len(raw):
                return None
            length = int.from_bytes(raw[offset : offset + 32], "big")
            start = offset + 32
            if length > 1024 or start + length > len(raw):
                return None
            text = raw[start : start + length].decode("utf-8", errors="replace")
        else:
            return None
    except (ValueError, OverflowError):
        return None
    cleaned = sanitize_text(text)
    return cleaned or None
