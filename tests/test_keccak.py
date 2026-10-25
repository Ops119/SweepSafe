import pytest

from sweepsafe.keccak import keccak256, keccak_hex, to_checksum_address


def test_empty_input_vector():
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_known_event_topic():
    assert keccak_hex("Transfer(address,address,uint256)") == (
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )


def test_multi_block_input_is_stable():
    # > 136 bytes forces more than one absorb block.
    digest = keccak256(b"a" * 300)
    assert len(digest) == 32
    assert digest == keccak256(b"a" * 300)
    assert digest != keccak256(b"a" * 301)


def test_eip55_vectors():
    for address in (
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ):
        assert to_checksum_address(address.lower()) == address


def test_checksum_rejects_garbage():
    with pytest.raises(ValueError):
        to_checksum_address("0x1234")
    with pytest.raises(ValueError):
        to_checksum_address("0x" + "zz" * 20)
