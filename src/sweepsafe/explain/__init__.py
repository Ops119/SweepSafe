"""Plain-English, template-based explanations (no LLM calls, fully offline)."""

from __future__ import annotations

import re

from sweepsafe.explain.format import format_amount, short_address
from sweepsafe.models import Approval, RiskResult
from sweepsafe.risk.rules import Rules, default_rules

_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def fill_template(template: str, values: dict[str, str]) -> str:
    """Single-pass substitution so hostile values (e.g. a token symbol "{spender}") stay inert."""
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(1), m.group(0)), template)


def token_label(approval: Approval) -> str:
    return approval.token_symbol or f"Token {short_address(approval.token)}"


def explain_approval(approval: Approval, risk: RiskResult, rules: Rules | None = None) -> str:
    rules = rules or default_rules()
    tpl = rules.explain
    values = {
        "symbol": token_label(approval),
        "allowance": format_amount(
            approval.allowance, approval.token_decimals, rules.unlimited_threshold
        ),
        "spender": short_address(approval.spender),
        "level": risk.level,
        "score": str(risk.score),
    }
    lines = [fill_template(tpl.headline, values), fill_template(tpl.risk_line, values)]
    if risk.findings:
        lines.extend(f"- {finding.message}" for finding in risk.findings)
    else:
        lines.append(f"- {tpl.no_findings}")
    lines.append(tpl.advice.get(risk.level, ""))
    return "\n".join(line for line in lines if line)


__all__ = ["explain_approval", "fill_template", "format_amount", "short_address", "token_label"]
