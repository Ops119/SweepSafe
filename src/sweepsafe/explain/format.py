"""Formatting helpers. Integer-only maths, so ``docs/sweepsafe.js`` (BigInt) matches exactly."""

from __future__ import annotations

MAX_DECIMALS = 77  # 10**77 < 2**256; anything larger is a broken or hostile token


def short_address(address: str) -> str:
    return f"{address[:6]}…{address[-4:]}"


def format_amount(value: int, decimals: int | None, unlimited_threshold: int) -> str:
    """Human readable token amount: ``unlimited``, ``1,234.5`` or ``<0.0001``."""
    if value >= unlimited_threshold:
        return "unlimited"
    if decimals is None or not 0 <= decimals <= MAX_DECIMALS:
        return f"{value} raw units"
    whole, frac = divmod(value, 10**decimals)
    frac_text = str(frac).zfill(decimals)[:4].rstrip("0") if decimals > 0 else ""
    if whole == 0 and value > 0 and not frac_text:
        return "<0.0001"
    return f"{whole:,}" + (f".{frac_text}" if frac_text else "")
