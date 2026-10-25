import pytest

from sweepsafe import abi
from sweepsafe.keccak import keccak_hex

OWNER = "0x" + "11" * 20
SPENDER = "0x" + "ab" * 20


def test_constants_match_their_signatures():
    assert "0x" + keccak_hex("Approval(address,address,uint256)") == abi.APPROVAL_TOPIC
    assert "0x" + keccak_hex("approve(address,uint256)")[:8] == abi.SELECTOR_APPROVE
    assert "0x" + keccak_hex("allowance(address,address)")[:8] == abi.SELECTOR_ALLOWANCE
    assert "0x" + keccak_hex("symbol()")[:8] == abi.SELECTOR_SYMBOL
    assert "0x" + keccak_hex("decimals()")[:8] == abi.SELECTOR_DECIMALS


def test_address_validation_and_normalisation():
    assert abi.is_address(OWNER)
    assert not abi.is_address("0x1234")
    assert not abi.is_address(None)
    assert abi.normalize_address("0x" + "AB" * 20) == "0x" + "ab" * 20
    with pytest.raises(abi.AbiError):
        abi.normalize_address("nope")


def test_topic_round_trip():
    topic = abi.address_to_topic(OWNER)
    assert len(topic) == 66
    assert topic.startswith("0x" + "0" * 24)
    assert abi.topic_to_address(topic) == OWNER
    with pytest.raises(abi.AbiError):
        abi.topic_to_address("0x1234")


def test_encode_approve_zero():
    data = abi.encode_approve(SPENDER, 0)
    assert data.startswith(abi.SELECTOR_APPROVE)
    assert len(data) == 2 + 8 + 64 + 64
    assert data.endswith("0" * 64)
    assert SPENDER[2:] in data


def test_encode_allowance_call_layout():
    data = abi.encode_allowance_call(OWNER, SPENDER)
    assert data.startswith(abi.SELECTOR_ALLOWANCE)
    assert len(data) == 2 + 8 + 128
    assert data[10:74].endswith(OWNER[2:])
    assert data[74:].endswith(SPENDER[2:])


def test_uint256_bounds():
    assert abi.encode_uint256(abi.MAX_UINT256) == "f" * 64
    with pytest.raises(abi.AbiError):
        abi.encode_uint256(-1)
    with pytest.raises(abi.AbiError):
        abi.encode_uint256(abi.MAX_UINT256 + 1)


def test_decode_uint256_strict():
    assert abi.decode_uint256("0x" + "00" * 31 + "05") == 5
    for bad in ("0x", "0x00", "0x" + "00" * 33, "zz", None):
        with pytest.raises(abi.AbiError):
            abi.decode_uint256(bad)


def test_decode_hex_int():
    assert abi.decode_hex_int("0x1b4") == 436
    with pytest.raises(abi.AbiError):
        abi.decode_hex_int("0x")
    with pytest.raises(abi.AbiError):
        abi.decode_hex_int(5)


def _abi_string(text: str) -> str:
    raw = text.encode()
    padded = raw.ljust(((len(raw) + 31) // 32) * 32, b"\x00")
    return "0x" + (32).to_bytes(32, "big").hex() + len(raw).to_bytes(32, "big").hex() + padded.hex()


def test_decode_string_variants():
    assert abi.decode_string(_abi_string("USDC")) == "USDC"
    assert abi.decode_string("0x" + b"MKR".ljust(32, b"\x00").hex()) == "MKR"


def test_decode_string_sanitises_hostile_input():
    hostile = abi.decode_string(_abi_string("<b>\x07evil\n" + "x" * 100))
    assert "\x07" not in hostile and "\n" not in hostile
    assert len(hostile) <= 32


def test_decode_string_rejects_malformed():
    assert abi.decode_string("0x") is None
    assert abi.decode_string("0x" + "00" * 10) is None
    assert abi.decode_string("zz") is None
    # offset pointing outside the buffer
    assert abi.decode_string("0x" + (10_000).to_bytes(32, "big").hex() + "00" * 32) is None
    # absurd length
    bad = "0x" + (32).to_bytes(32, "big").hex() + (10**9).to_bytes(32, "big").hex()
    assert abi.decode_string(bad) is None
    # empty string -> None
    assert abi.decode_string(_abi_string("")) is None
