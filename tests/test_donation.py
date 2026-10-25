"""The donation address appears in several files; they must agree and be well formed."""

import re
from pathlib import Path

from sweepsafe.solana import b58decode, is_solana_address

ROOT = Path(__file__).resolve().parent.parent
ADDRESS = "75DDnCQt4HPP5bF55oSBvSrwuCSLcC7U2w9tc3kMmyrA"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
BASE58_ADDRESS = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{43,44}\b")


def test_addresses_are_valid():
    assert is_solana_address(ADDRESS) and is_solana_address(USDC_MINT)
    assert b58decode(USDC_MINT).hex().startswith("c6fa7af3bedbad3a3d65f36aabc97431")


def test_donate_js_and_readme_agree():
    js = (ROOT / "docs/donate.js").read_text()
    assert f'var ADDRESS = "{ADDRESS}"' in js and f'var USDC_MINT = "{USDC_MINT}"' in js
    assert "var MAX = 10000" in js and "var MIN = 1" in js
    assert ADDRESS in (ROOT / "README.md").read_text()


def test_no_other_payment_address_anywhere_in_the_site():
    allowed = {ADDRESS, USDC_MINT}
    for path in (ROOT / "docs").glob("*"):
        if path.suffix not in {".html", ".js", ".css"} or path.name == "sweepsafe.js":
            continue
        found = {m for m in BASE58_ADDRESS.findall(path.read_text()) if is_solana_address(m)}
        assert found <= allowed, f"{path.name}: unexpected address {found - allowed}"


def test_pages_load_the_widget_and_keep_a_strict_csp():
    for name in ("index.html", "report.html"):
        html = (ROOT / "docs" / name).read_text()
        assert 'id="donate"' in html and '<script src="donate.js">' in html
        assert "script-src 'self'" in html and "unsafe-inline" not in html and "<style" not in html
