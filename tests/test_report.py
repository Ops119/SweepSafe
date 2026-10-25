import re
from html import unescape

from fakes import OWNER, SPENDER_1, TOKEN_A
from scenarios import NOW, wallet_node
from sweepsafe.config import get_chain
from sweepsafe.explain import explain_approval
from sweepsafe.models import Approval, RiskResult, ScanResult, ScoredApproval, Verification
from sweepsafe.report import render_report
from sweepsafe.risk import RiskEngine, RiskInput
from sweepsafe.service import scan_wallet
from sweepsafe.store import Store

XSS = '<script>alert("pwn")</script><img src=x onerror=alert(1)>'


def scored(symbol, spender=SPENDER_1, **kw):
    approval = Approval(
        chain="ethereum",
        owner=OWNER,
        token=TOKEN_A,
        spender=spender,
        allowance=(1 << 256) - 1,
        block_number=1,
        tx_hash="0x01",
        token_symbol=symbol,
        token_decimals=18,
        spender_is_contract=True,
        verification=Verification.UNVERIFIED,
        **kw,
    )
    risk = RiskEngine().evaluate(
        RiskInput(
            allowance=approval.allowance,
            spender_is_contract=True,
            verification=Verification.UNVERIFIED,
            blocklisted=False,
            age_days=None,
        )
    )
    return ScoredApproval(
        approval=approval, risk=risk, explanation=explain_approval(approval, risk)
    )


def result(items, warnings=(), chain="ethereum", owner=OWNER):
    return ScanResult(
        chain=chain,
        chain_id=1,
        owner=owner,
        scanned_to_block=123,
        generated_at=NOW,
        approvals=list(items),
        warnings=list(warnings),
    )


def test_hostile_token_symbol_is_escaped_everywhere():
    html = render_report(result([scored(XSS)], warnings=[XSS]))
    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "&lt;script&gt;" in html
    assert "onerror" in html  # present only as inert escaped text
    assert not re.search(r"<[^>]*onerror=", html)


def test_hostile_owner_and_chain_strings_are_escaped():
    html = render_report(result([], chain=XSS, owner=XSS))
    assert "<script" not in html.lower() and "<img" not in html.lower()


def test_report_is_self_contained_and_script_free():
    html = render_report(result([scored("USDC")]))
    assert "<script" not in html.lower()
    assert 'http-equiv="Content-Security-Policy"' in html
    assert "default-src 'none'" in unescape(html)  # quotes are entity-escaped inside the attribute
    assert not re.search(r'(src|href)="https?://(?!etherscan)', html)  # only explorer links
    assert html.startswith("<!doctype html>")


def test_report_content_and_viewer_link():
    html = render_report(result([scored("USDC")]), pages_url="https://me.github.io/SweepSafe/")
    assert "USDC: unlimited" in html
    assert "critical: 0" in html and "high: 1" in html
    assert "Scanned to block 123" in html
    assert f"https://me.github.io/SweepSafe/report.html#ethereum:{OWNER}" in html
    assert f'href="https://etherscan.io/address/{SPENDER_1}"' in html
    assert 'rel="noopener noreferrer"' in html
    assert "never asks for your seed phrase" in html


def test_empty_report_and_unknown_chain_have_no_explorer_link():
    empty = render_report(result([]))
    assert "No active token approvals" in empty
    html = render_report(result([scored("X")], chain="mystery"))
    assert "etherscan" not in html and "/address/" not in html


def test_warnings_rendered():
    html = render_report(result([], warnings=["Could not read allowance"]))
    assert "Could not read allowance" in html and "Heads up" in html


def test_full_scan_renders_every_approval_sorted_by_risk():
    node = wallet_node()
    with Store(":memory:") as store:
        scan = scan_wallet(
            OWNER,
            get_chain("ethereum"),
            reader=node,
            store=store,
            verifier=type("V", (), {"check": lambda self, c, a: Verification.UNVERIFIED})(),
            now=lambda: NOW,
        )
    html = render_report(scan)
    assert html.count('class="card"') >= 3
    assert html.index("HIGH 70") < html.index("MEDIUM 30")


def test_unknown_level_falls_back_safely():
    item = scored("USDC")
    item = item.model_copy(update={"risk": RiskResult(score=5, level="weird")})
    html = render_report(result([item]))
    assert 'class="badge low"' in html
