"""Static-site invariants that are easy to break by accident."""

from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"


def test_scanner_loads_scripts_in_dependency_order():
    html = (DOCS / "report.html").read_text()
    order = ["sweepsafe.js", "wallets.js", "app.js", "donate.js"]
    positions = [html.index(f'<script src="{name}">') for name in order]
    assert positions == sorted(positions)


def test_pages_stay_free_of_inline_code_and_remote_scripts():
    for page in DOCS.glob("*.html"):
        html = page.read_text()
        assert "unsafe-inline" not in html and "<style" not in html, page.name
        assert "javascript:" not in html and " onclick=" not in html, page.name
        assert 'script src="http' not in html, page.name


def test_wallet_names_are_never_rendered_as_html():
    for name in ("app.js", "wallets.js"):
        text = (DOCS / name).read_text()
        assert "innerHTML" not in text and "insertAdjacentHTML" not in text, name
