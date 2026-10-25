"""Python and the web viewer must agree on every constant that affects risk or data access."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sweepsafe.abi import APPROVAL_TOPIC
from sweepsafe.chains import rpc as py_rpc
from sweepsafe.config import CHAINS
from sweepsafe.config.settings import DEFAULT_BLOCKLIST_URLS
from sweepsafe.keccak import keccak_hex
from sweepsafe.sources import verification as py_verification

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def js_constants() -> dict:
    script = (
        "const S=require(process.argv[1]);"
        "console.log(JSON.stringify({chains:S.CHAINS,blocklists:S.BLOCKLIST_URLS,topic:S.APPROVAL_TOPIC,"
        "selectors:S.SELECTORS,range:S.RANGE_HINTS,rate:S.RATE_HINTS,revert:S.REVERT_HINTS,"
        "sourcify:S.SOURCIFY_BASE,aliases:Object.fromEntries(Object.keys(S.CHAINS).concat(['eth','mainnet','arb','arbitrum-one','op','matic','bsc','bnb-chain','avax']).map(k=>[k,S.getChain(k).name]))}))"
    )
    out = subprocess.run(
        ["node", "-e", script, str(DOCS / "sweepsafe.js")],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    return json.loads(out)


def test_rules_json_copies_are_identical():
    assert (DOCS / "rules.json").read_bytes() == (
        ROOT / "src/sweepsafe/data/rules.json"
    ).read_bytes()


def test_chains_match():
    js = js_constants()["chains"]
    assert set(js) == set(CHAINS)
    for name, chain in CHAINS.items():
        j = js[name]
        assert (
            j["id"],
            list(j["rpcs"]),
            j["explorer"],
            j["blockscout"],
            j["reorgDepth"],
            j["startBlock"],
        ) == (
            chain.chain_id,
            list(chain.rpcs),
            chain.explorer,
            chain.blockscout,
            chain.reorg_depth,
            chain.start_block,
        )


def test_lists_and_urls_match():
    js = js_constants()
    assert tuple(js["blocklists"]) == tuple(DEFAULT_BLOCKLIST_URLS)
    assert js["sourcify"] == py_verification.SOURCIFY_BASE
    assert tuple(js["range"]) == tuple(py_rpc._RANGE_HINTS)
    assert tuple(js["rate"]) == tuple(py_rpc._RATE_HINTS)
    assert tuple(js["revert"]) == tuple(py_rpc._REVERT_HINTS)


def test_abi_constants_match_and_are_keccak_derived():
    js = js_constants()
    assert js["topic"] == APPROVAL_TOPIC
    assert js["topic"] == "0x" + keccak_hex("Approval(address,address,uint256)")
    expected = {
        "approve": "approve(address,uint256)",
        "allowance": "allowance(address,address)",
        "symbol": "symbol()",
        "decimals": "decimals()",
    }
    for key, sig in expected.items():
        assert js["selectors"][key] == "0x" + keccak_hex(sig)[:8]


def test_aliases_resolve_identically():
    from sweepsafe.config import get_chain

    for alias, name in js_constants()["aliases"].items():
        assert get_chain(alias).name == name
