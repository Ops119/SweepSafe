import json
from pathlib import Path

import pytest

from sweepsafe.models import Verification
from sweepsafe.risk import RiskEngine, RiskInput, age_in_days, default_rules, parse_rules

FIXTURES = Path(__file__).parent / "fixtures"
MAX_UINT = (1 << 256) - 1


def _input(**overrides):
    base = {
        "allowance": 1_000,
        "spender_is_contract": True,
        "verification": Verification.VERIFIED,
        "blocklisted": False,
        "age_days": 10,
    }
    base.update(overrides)
    return RiskInput(**base)


def ids(result):
    return [f.rule_id for f in result.findings]


def test_clean_approval_scores_zero_low():
    result = RiskEngine().evaluate(_input())
    assert result.score == 0
    assert result.level == "low"
    assert result.findings == []


def test_each_rule_fires_independently():
    engine = RiskEngine()
    assert ids(engine.evaluate(_input(allowance=MAX_UINT))) == ["unlimited_allowance"]
    assert ids(engine.evaluate(_input(spender_is_contract=False))) == ["spender_is_eoa"]
    assert ids(engine.evaluate(_input(verification=Verification.UNVERIFIED))) == [
        "unverified_contract"
    ]
    assert ids(engine.evaluate(_input(verification=Verification.UNKNOWN))) == [
        "unknown_verification"
    ]
    assert ids(engine.evaluate(_input(blocklisted=True))) == ["blocklisted_spender"]
    assert ids(engine.evaluate(_input(age_days=181))) == ["stale_approval"]


def test_unlimited_threshold_boundary():
    engine = RiskEngine()
    threshold = default_rules().unlimited_threshold
    assert ids(engine.evaluate(_input(allowance=threshold - 1))) == []
    assert ids(engine.evaluate(_input(allowance=threshold))) == ["unlimited_allowance"]


def test_stale_boundary_is_exclusive():
    engine = RiskEngine()
    assert ids(engine.evaluate(_input(age_days=180))) == []
    assert ids(engine.evaluate(_input(age_days=181))) == ["stale_approval"]
    assert ids(engine.evaluate(_input(age_days=None))) == []


def test_unknown_contractness_suppresses_contract_only_rules():
    result = RiskEngine().evaluate(
        _input(spender_is_contract=None, verification=Verification.UNVERIFIED)
    )
    assert result.findings == []


def test_eoa_does_not_also_get_verification_findings():
    result = RiskEngine().evaluate(
        _input(spender_is_contract=False, verification=Verification.UNVERIFIED)
    )
    assert ids(result) == ["spender_is_eoa"]


def test_score_is_capped_at_100_and_levels():
    result = RiskEngine().evaluate(
        _input(allowance=MAX_UINT, spender_is_contract=False, blocklisted=True, age_days=999)
    )
    assert result.score == 100
    assert result.level == "critical"


@pytest.mark.parametrize(
    ("score", "level"),
    [(0, "low"), (24, "low"), (25, "medium"), (49, "medium"), (50, "high"), (74, "high"),
     (75, "critical"), (100, "critical")],
)  # fmt: skip
def test_level_boundaries(score, level):
    assert default_rules().level_for(score) == level


def test_stale_message_includes_days():
    result = RiskEngine().evaluate(_input(age_days=400))
    assert "400 days" in result.findings[0].message


def test_add_rule_requires_rules_json_entry():
    engine = RiskEngine()
    with pytest.raises(KeyError):
        engine.add_rule("made_up", lambda inp, rules: None)


def test_custom_rule_plugs_in():
    raw = json.loads((Path(__file__).parents[1] / "src/sweepsafe/data/rules.json").read_text())
    raw["rules"]["tiny_allowance"] = {"weight": 7, "message": "tiny"}
    engine = RiskEngine(parse_rules(json.dumps(raw)))
    engine.add_rule("tiny_allowance", lambda inp, rules: "tiny" if inp.allowance < 10 else None)
    result = engine.evaluate(_input(allowance=5))
    assert result.score == 7


def test_rules_without_builtin_are_ignored_and_disabled_rules_skip():
    raw = json.loads((Path(__file__).parents[1] / "src/sweepsafe/data/rules.json").read_text())
    del raw["rules"]["spender_is_eoa"]
    engine = RiskEngine(parse_rules(json.dumps(raw)))
    assert engine.evaluate(_input(spender_is_contract=False)).findings == []


def test_age_in_days():
    assert age_in_days(None, 1_000) is None
    assert age_in_days(0, 86_400 * 3 + 5) == 3
    assert age_in_days(2_000, 1_000) == 0  # clock skew never goes negative


def test_rules_validation_rejects_bad_levels():
    raw = json.loads((Path(__file__).parents[1] / "src/sweepsafe/data/rules.json").read_text())
    raw["levels"] = [{"name": "only", "min": 10}]
    with pytest.raises(ValueError):
        parse_rules(json.dumps(raw))
    raw["levels"] = []
    with pytest.raises(ValueError):
        parse_rules(json.dumps(raw))


def test_rules_threshold_must_be_decimal_string_or_int():
    raw = json.loads((Path(__file__).parents[1] / "src/sweepsafe/data/rules.json").read_text())
    raw["unlimited_threshold"] = 5.5
    with pytest.raises(ValueError):
        parse_rules(json.dumps(raw))


def test_parity_cases_python_side():
    """The same cases are asserted by the JavaScript tests; both must agree."""
    from sweepsafe.explain import explain_approval
    from sweepsafe.models import Approval

    cases = json.loads((FIXTURES / "parity_cases.json").read_text())
    rules = default_rules()
    engine = RiskEngine(rules)
    assert cases, "fixture must not be empty"
    for case in cases:
        inp = case["input"]
        risk = engine.evaluate(
            RiskInput(
                allowance=int(inp["allowance"]),
                spender_is_contract=inp["spender_is_contract"],
                verification=Verification(inp["verification"]),
                blocklisted=inp["blocklisted"],
                age_days=inp["age_days"],
            )
        )
        expected = case["expected"]
        assert risk.score == expected["score"], case["name"]
        assert risk.level == expected["level"], case["name"]
        assert ids(risk) == expected["rule_ids"], case["name"]
        approval = Approval(
            chain="ethereum",
            owner="0x" + "11" * 20,
            token=case["token"],
            spender=case["spender"],
            allowance=int(inp["allowance"]),
            block_number=1,
            tx_hash="0x00",
            token_symbol=case["token_symbol"],
            token_decimals=case["token_decimals"],
        )
        assert explain_approval(approval, risk, rules) == expected["explanation"], case["name"]
