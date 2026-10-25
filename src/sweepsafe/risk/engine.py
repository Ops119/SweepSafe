"""Pluggable rule engine. Built-in rules mirror ``docs/sweepsafe.js`` (see the parity tests)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sweepsafe.models import RiskFinding, RiskResult, Verification
from sweepsafe.risk.rules import Rules, default_rules

SECONDS_PER_DAY = 86_400


@dataclass(frozen=True)
class RiskInput:
    """Everything a rule may look at. ``None`` means "we could not determine this"."""

    allowance: int
    spender_is_contract: bool | None
    verification: Verification
    blocklisted: bool
    age_days: int | None


# A rule returns a finding message (already formatted) or None when it does not apply.
Rule = Callable[[RiskInput, Rules], str | None]


def _blocklisted(inp: RiskInput, rules: Rules) -> str | None:
    return rules.rules["blocklisted_spender"].message if inp.blocklisted else None


def _eoa(inp: RiskInput, rules: Rules) -> str | None:
    return rules.rules["spender_is_eoa"].message if inp.spender_is_contract is False else None


def _unlimited(inp: RiskInput, rules: Rules) -> str | None:
    if inp.allowance >= rules.unlimited_threshold:
        return rules.rules["unlimited_allowance"].message
    return None


def _unverified(inp: RiskInput, rules: Rules) -> str | None:
    if inp.spender_is_contract is True and inp.verification is Verification.UNVERIFIED:
        return rules.rules["unverified_contract"].message
    return None


def _unknown_verification(inp: RiskInput, rules: Rules) -> str | None:
    if inp.spender_is_contract is True and inp.verification is Verification.UNKNOWN:
        return rules.rules["unknown_verification"].message
    return None


def _stale(inp: RiskInput, rules: Rules) -> str | None:
    if inp.age_days is not None and inp.age_days > rules.stale_days:
        return rules.rules["stale_approval"].message.replace("{days}", str(inp.age_days))
    return None


BUILTIN_RULES: dict[str, Rule] = {
    "blocklisted_spender": _blocklisted,
    "spender_is_eoa": _eoa,
    "unlimited_allowance": _unlimited,
    "unverified_contract": _unverified,
    "unknown_verification": _unknown_verification,
    "stale_approval": _stale,
}


def age_in_days(timestamp: int | None, now: int) -> int | None:
    """Whole days between ``timestamp`` and ``now`` (None if unknown, never negative)."""
    if timestamp is None:
        return None
    return max(0, (now - timestamp) // SECONDS_PER_DAY)


class RiskEngine:
    """Scores an approval 0-100. Rules are looked up by id in ``rules.json`` for weight/message.

    Extra rules can be plugged in with :meth:`add_rule`; they need a matching ``rules.json``
    entry so their weight and wording stay configurable.
    """

    def __init__(self, rules: Rules | None = None) -> None:
        self.rules = rules or default_rules()
        self._registry: dict[str, Rule] = {
            rule_id: fn for rule_id, fn in BUILTIN_RULES.items() if rule_id in self.rules.rules
        }

    def add_rule(self, rule_id: str, fn: Rule) -> None:
        if rule_id not in self.rules.rules:
            raise KeyError(f"rule {rule_id!r} has no entry in rules.json")
        self._registry[rule_id] = fn

    def evaluate(self, inp: RiskInput) -> RiskResult:
        findings: list[RiskFinding] = []
        for rule_id, fn in self._registry.items():
            message = fn(inp, self.rules)
            if message is not None:
                findings.append(
                    RiskFinding(
                        rule_id=rule_id, weight=self.rules.rules[rule_id].weight, message=message
                    )
                )
        score = min(100, sum(f.weight for f in findings))
        return RiskResult(score=score, level=self.rules.level_for(score), findings=findings)
