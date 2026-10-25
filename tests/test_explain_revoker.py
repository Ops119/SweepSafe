import pytest

from sweepsafe.config.chains import BASE, ETHEREUM
from sweepsafe.explain import fill_template, token_label
from sweepsafe.explain.format import MAX_DECIMALS, format_amount, short_address
from sweepsafe.models import Approval, RiskResult, ScoredApproval
from sweepsafe.revoker import build_revoke_tx, build_revoke_txs, select_for_revoke

THRESHOLD = 1 << 255
TOKEN = "0x" + "aa" * 20
TOKEN_2 = "0x" + "bb" * 20
SPENDER = "0x" + "c1" * 20
SPENDER_2 = "0x" + "c2" * 20
OWNER = "0x" + "11" * 20


@pytest.mark.parametrize(
    ("value", "decimals", "expected"),
    [
        (0, 18, "0"),
        (1, 18, "<0.0001"),
        (1, 0, "1"),
        (10**18, 18, "1"),
        (1_500_000, 6, "1.5"),
        (1234567, 3, "1,234.567"),
        (123, 6, "0.0001"),  # truncates to 4 dp, never rounds up
        (99, 6, "<0.0001"),
        (100_000_000_000, 6, "100,000"),
        (5, None, "5 raw units"),
        (5, 78, "5 raw units"),
        (THRESHOLD, 18, "unlimited"),
        (THRESHOLD - 1, None, f"{THRESHOLD - 1} raw units"),
    ],
)
def test_format_amount(value, decimals, expected):
    assert format_amount(value, decimals, THRESHOLD) == expected


def test_format_amount_extreme_decimals_do_not_crash():
    # 5e76 is just under the unlimited threshold (2**255 ~ 5.79e76); 77 decimals is the maximum.
    assert format_amount(5 * 10**76, MAX_DECIMALS, THRESHOLD) == "0.5"
    assert format_amount(10**MAX_DECIMALS, MAX_DECIMALS, THRESHOLD) == "unlimited"


def test_short_address():
    assert short_address(SPENDER) == "0xc1c1…c1c1"


def test_fill_template_is_single_pass():
    assert fill_template("{a} {b} {missing}", {"a": "{b}", "b": "x"}) == "{b} x {missing}"


def approval(**kw):
    base = {
        "chain": "base",
        "owner": OWNER,
        "token": TOKEN,
        "spender": SPENDER,
        "allowance": 5,
        "block_number": 1,
        "tx_hash": "0x01",
    }
    base.update(kw)
    return Approval(**base)


def scored(score, **kw):
    return ScoredApproval(
        approval=approval(**kw),
        risk=RiskResult(score=score, level="low"),
        explanation="",
    )


def test_token_label_fallback():
    assert token_label(approval(token_symbol="USDC")) == "USDC"
    assert token_label(approval()) == "Token 0xaaaa…aaaa"


def test_revoke_tx_sets_allowance_to_zero_on_token_contract():
    tx = build_revoke_tx(BASE, approval(token_symbol="USDC"))
    assert tx.chain_id == 8453
    assert tx.to == TOKEN
    assert tx.data == "0x095ea7b3" + SPENDER[2:].rjust(64, "0") + "0" * 64
    assert tx.value == "0x0"
    assert "USDC" in tx.description
    assert tx.as_wallet_request() == {
        "to": TOKEN,
        "data": tx.data,
        "value": "0x0",
        "chainId": "0x2105",
    }


def test_revoke_tx_rejects_chain_mismatch():
    with pytest.raises(ValueError):
        build_revoke_tx(ETHEREUM, approval(chain="base"))


def test_revoke_tx_rejects_bad_addresses():
    with pytest.raises(ValueError):
        build_revoke_tx(BASE, approval(token="not-an-address"))


def test_select_for_revoke_filters():
    items = [
        scored(80),
        scored(30, token=TOKEN_2),
        scored(10, spender=SPENDER_2),
    ]
    assert len(select_for_revoke(items)) == 3
    assert len(select_for_revoke(items, min_score=30)) == 2
    assert [
        i.approval.token
        for i in select_for_revoke(items, token=TOKEN_2.upper().replace("0X", "0x"))
    ] == [TOKEN_2]
    assert [i.approval.spender for i in select_for_revoke(items, spender=SPENDER_2)] == [SPENDER_2]
    assert select_for_revoke(items, min_score=99) == []


def test_build_revoke_txs_batches():
    txs = build_revoke_txs(BASE, [scored(50), scored(60, spender=SPENDER_2)])
    assert [t.data[10:74][-40:] for t in txs] == [SPENDER[2:], SPENDER_2[2:]]
