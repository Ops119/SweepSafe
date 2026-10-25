"""Static, self-contained HTML report. No JavaScript; every dynamic value is HTML-escaped.

Token symbols and names are controlled by whoever deployed the token, so they are treated as
hostile input everywhere they are rendered.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape

from sweepsafe.config.chains import CHAINS
from sweepsafe.config.settings import DEFAULT_PAGES_URL
from sweepsafe.explain.format import format_amount, short_address
from sweepsafe.models import ScanResult, ScoredApproval
from sweepsafe.risk.rules import Rules, default_rules
from sweepsafe.solana.scan import SOLANA_EXPLORER

_CSS = """
:root{--bg:#fff;--fg:#15171a;--muted:#5b6470;--card:#f5f6f8;--line:#dde1e7;
--critical:#b00020;--high:#c2410c;--medium:#a16207;--low:#166534}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e8eaed;--muted:#9aa3af;--card:#181b21;
--line:#2a2f38;--critical:#ff6b81;--high:#fb923c;--medium:#facc15;--low:#4ade80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:760px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.05rem;margin:0}
.muted{color:var(--muted);font-size:.9rem}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;
word-break:break-all}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.chip{border:1px solid var(--line);border-radius:999px;padding:2px 12px;font-size:.9rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;
margin:12px 0}
.row{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.badge{border:2px solid currentColor;border-radius:8px;padding:0 8px;font-weight:700;
white-space:nowrap}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}
.low{color:var(--low)}ul{margin:8px 0 8px 20px;padding:0}
.note{border-left:4px solid var(--medium);padding:4px 12px;margin:16px 0}
a{color:inherit}
"""

_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)


def _level_class(level: str, rules: Rules) -> str:
    return level if level in {lv.name for lv in rules.levels} else "low"


def _render_item(item: ScoredApproval, explorer: str | None, rules: Rules) -> str:
    a = item.approval
    amount = format_amount(a.allowance, a.token_decimals, rules.unlimited_threshold)
    label = a.token_symbol or f"Token {short_address(a.token)}"
    level = _level_class(item.risk.level, rules)
    spender = escape(short_address(a.spender))
    if explorer:
        path = "account" if a.chain == "solana" else "address"
        spender = (
            f'<a href="{escape(explorer, quote=True)}/{path}/{escape(a.spender, quote=True)}" '
            f'target="_blank" rel="noopener noreferrer">{spender}</a>'
        )
    findings = "".join(f"<li>{escape(f.message)}</li>" for f in item.risk.findings)
    if not findings:
        findings = f"<li>{escape(rules.explain.no_findings)}</li>"
    advice = escape(rules.explain.advice.get(item.risk.level, ""))
    return (
        '<section class="card">'
        f'<div class="row"><h2>{escape(label)}: {escape(amount)}</h2>'
        f'<span class="badge {level}">'
        f"{escape(item.risk.level.upper())} {item.risk.score}</span></div>"
        f'<p class="muted">Spender {spender} on {escape(a.chain)}</p>'
        f"<ul>{findings}</ul><p><strong>{advice}</strong></p></section>"
    )


def render_report(
    result: ScanResult, *, pages_url: str = DEFAULT_PAGES_URL, rules: Rules | None = None
) -> str:
    rules = rules or default_rules()
    if result.chain == "solana":
        explorer = SOLANA_EXPLORER
    else:
        explorer = CHAINS[result.chain].explorer if result.chain in CHAINS else None
    counts = {lv.name: 0 for lv in rules.levels}
    for item in result.approvals:
        counts[item.risk.level] = counts.get(item.risk.level, 0) + 1
    chips = "".join(
        f'<span class="chip {_level_class(name, rules)}">{escape(name)}: {n}</span>'
        for name, n in counts.items()
    )
    items = "".join(_render_item(i, explorer, rules) for i in result.approvals) or (
        '<p class="card">No active token approvals found for this wallet on this chain.</p>'
    )
    warnings = ""
    if result.warnings:
        warnings = (
            '<div class="note"><strong>Heads up</strong><ul>'
            + "".join(f"<li>{escape(w)}</li>" for w in result.warnings)
            + "</ul></div>"
        )
    when = datetime.fromtimestamp(result.generated_at, UTC).strftime("%Y-%m-%d %H:%M UTC")
    viewer = f"{pages_url.rstrip('/')}/report.html#{result.chain}:{result.owner}"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{escape(_CSP, quote=True)}">'
        "<title>SweepSafe report</title>"
        f"<style>{_CSS}</style></head><body><main>"
        "<h1>SweepSafe report</h1>"
        f'<p class="muted mono">{escape(result.owner)} on {escape(result.chain)}</p>'
        f'<p class="muted">Scanned to block {result.scanned_to_block} &middot; {escape(when)}</p>'
        f'<div class="chips">{chips}</div>{warnings}{items}'
        '<p class="note">SweepSafe never asks for your seed phrase or private key. '
        "Revoking happens in your own wallet.</p>"
        f'<p class="muted">Re-check live: <span class="mono">{escape(viewer)}</span></p>'
        "</main></body></html>"
    )
