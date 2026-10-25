"""Pure-Python Keccak-256 (the original Keccak padding used by Ethereum, not NIST SHA3).

Only used for tiny inputs (event signatures, EIP-55 address checksums), so clarity beats speed.
This keeps SweepSafe free of third-party crypto dependencies, and lets the test-suite verify
every hard-coded selector/topic constant against its human-readable signature.
"""

from __future__ import annotations

_MASK = (1 << 64) - 1
_RATE = 136  # bytes; (1600 - 2 * 256) / 8

_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

# Rotation offsets indexed [x][y].
_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rol(value: int, shift: int) -> int:
    if shift == 0:
        return value
    return ((value << shift) | (value >> (64 - shift))) & _MASK


def _permute(a: list[list[int]]) -> None:
    for rc in _ROUND_CONSTANTS:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROTATIONS[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Return the 32-byte Keccak-256 digest of ``data``."""
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _RATE:
        padded.append(0x00)
    padded[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), _RATE):
        block = padded[offset : offset + _RATE]
        for i in range(_RATE // 8):
            lane = int.from_bytes(block[8 * i : 8 * i + 8], "little")
            state[i % 5][i // 5] ^= lane
        _permute(state)

    out = b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out[:32]


def keccak_hex(text: str) -> str:
    """Hex digest (no 0x prefix) of a UTF-8 string, e.g. an event or function signature."""
    return keccak256(text.encode()).hex()


def to_checksum_address(address: str) -> str:
    """EIP-55 mixed-case checksum encoding of a 20-byte hex address."""
    body = address.lower().removeprefix("0x")
    if len(body) != 40 or any(ch not in "0123456789abcdef" for ch in body):
        raise ValueError(f"not a 20-byte hex address: {address!r}")
    digest = keccak256(body.encode()).hex()
    return "0x" + "".join(
        ch.upper() if int(digest[i], 16) >= 8 else ch for i, ch in enumerate(body)
    )
