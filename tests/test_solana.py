import base64
import json

import pytest

from sweepsafe import cli
from sweepsafe.chains import RpcError
from sweepsafe.chains.rpc import RpcClient
from sweepsafe.models import Approval
from sweepsafe.report import render_report
from sweepsafe.solana import (
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    Base58Error,
    b58decode,
    b58encode,
    build_revoke_message,
    build_revoke_tx,
    is_solana_address,
    scan_solana,
)
from sweepsafe.solana.scan import SYSTEM_PROGRAM

OWNER = b58encode(bytes([1] * 32))
MINT_A = b58encode(bytes([2] * 32))
MINT_B = b58encode(bytes([3] * 32))
ACCT_A = b58encode(bytes([4] * 32))
ACCT_B = b58encode(bytes([5] * 32))
ACCT_C = b58encode(bytes([6] * 32))
WALLET_DELEGATE = b58encode(bytes([7] * 32))
PROGRAM_DELEGATE = b58encode(bytes([8] * 32))
BLOCKHASH = b58encode(bytes([9] * 32))
U64_MAX = 2**64 - 1


def token_entry(pubkey, mint, delegate=None, delegated="0", decimals=6):
    info = {
        "mint": mint,
        "owner": OWNER,
        "tokenAmount": {"amount": "5", "decimals": decimals},
    }
    if delegate:
        info["delegate"] = delegate
        info["delegatedAmount"] = {"amount": delegated, "decimals": decimals}
    else:
        info["delegatedAmount"] = {"amount": "0", "decimals": decimals}
    return {"pubkey": pubkey, "account": {"data": {"parsed": {"info": info}}}}


class FakeSolana:
    """Implements just the JSON-RPC calls a scan makes."""

    def __init__(self, token_accounts, token2022_accounts=(), fail_info=False):
        self.by_program = {
            TOKEN_PROGRAM: list(token_accounts),
            TOKEN_2022_PROGRAM: list(token2022_accounts),
        }
        self.fail_info = fail_info
        self.calls = []

    def call(self, method, params=None):
        self.calls.append(method)
        if method == "getTokenAccountsByOwner":
            return {"value": self.by_program[params[1]["programId"]]}
        if method == "getSlot":
            return 4242
        if method == "getLatestBlockhash":
            return {"value": {"blockhash": BLOCKHASH}}
        if method == "getAccountInfo":
            if self.fail_info:
                raise RpcError(-32000, "node is behind")
            address = params[0]
            if address == PROGRAM_DELEGATE:
                return {"value": {"executable": True, "owner": "BPFLoader"}}
            if address == WALLET_DELEGATE:
                return {"value": {"executable": False, "owner": SYSTEM_PROGRAM}}
            return {"value": None}
        raise AssertionError(method)


def wallet():
    return FakeSolana(
        [
            token_entry(ACCT_A, MINT_A, PROGRAM_DELEGATE, str(U64_MAX)),
            token_entry(ACCT_B, MINT_B, WALLET_DELEGATE, "1500000"),
            token_entry(ACCT_C, MINT_B),  # no delegate: ignored
        ],
        [token_entry(ACCT_C, MINT_A, PROGRAM_DELEGATE, "7")],
    )


def test_base58_known_vectors():
    assert b58encode(b"Hello World!") == "2NEpo7TZRRrLZSi2U"
    assert b58decode("2NEpo7TZRRrLZSi2U") == b"Hello World!"
    assert b58encode(b"\0\0\x01") == "112"
    assert b58decode("112") == b"\0\0\x01"
    for bad in ("", "0OIl", "abc!"):
        with pytest.raises(Base58Error):
            b58decode(bad)


def test_program_ids_decode_to_the_known_bytes():
    assert b58decode(TOKEN_PROGRAM).hex() == (
        "06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9"
    )
    assert b58decode(TOKEN_2022_PROGRAM).hex() == (
        "06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfc"
    )
    assert b58decode(SYSTEM_PROGRAM) == bytes(32)


def test_address_validation():
    assert is_solana_address(OWNER) and is_solana_address(TOKEN_PROGRAM)
    assert not is_solana_address("0x" + "11" * 20)
    assert not is_solana_address(b58encode(bytes(31)))
    assert not is_solana_address("") and not is_solana_address(None)


def test_scan_scores_and_orders_delegations():
    result = scan_solana(OWNER, reader=wallet(), now=lambda: 1_800_000_000)
    assert result.chain == "solana" and result.scanned_to_block == 4242
    got = [(a.approval.token_account, a.risk.score, a.risk.level) for a in result.approvals]
    # unlimited (35) + program with unknown verification (5) = 40; wallet delegate = 30; 7 units
    # to a program = 5.
    assert got == [(ACCT_A, 40, "medium"), (ACCT_B, 30, "medium"), (ACCT_C, 5, "low")]
    top = result.approvals[0]
    assert top.approval.token_program == TOKEN_PROGRAM
    assert result.approvals[2].approval.token_program == TOKEN_2022_PROGRAM
    assert "unlimited" in top.explanation
    assert "1.5" in result.approvals[1].explanation
    assert any("blocklist" in w for w in result.warnings)


def test_scan_ignores_malformed_accounts_and_survives_lookup_failure():
    bad = [
        {"pubkey": ACCT_A},
        {"pubkey": "short", "account": {"data": {"parsed": {"info": {}}}}},
        token_entry(ACCT_B, MINT_A, "not-an-address", "5"),
        token_entry(ACCT_B, MINT_A, WALLET_DELEGATE, "-3"),
        token_entry(ACCT_B, MINT_A, WALLET_DELEGATE, "abc"),
        token_entry(ACCT_B, MINT_A, WALLET_DELEGATE, "1_000"),
        token_entry(ACCT_B, MINT_A, WALLET_DELEGATE, " 5 "),
        token_entry(ACCT_B, MINT_A, WALLET_DELEGATE, "+5"),
        token_entry(ACCT_B, MINT_A, WALLET_DELEGATE, "\u0665"),
        token_entry(ACCT_B, "bad-mint", WALLET_DELEGATE, "5"),
    ]
    assert scan_solana(OWNER, reader=FakeSolana(bad)).approvals == []
    result = scan_solana(
        OWNER,
        reader=FakeSolana([token_entry(ACCT_A, MINT_A, WALLET_DELEGATE, "5")], fail_info=True),
    )
    assert result.approvals[0].approval.spender_is_contract is None
    assert any("Could not tell" in w for w in result.warnings)


def test_scan_rejects_bad_owner_and_odd_shapes():
    with pytest.raises(ValueError):
        scan_solana("0x1234", reader=wallet())

    class Weird:
        def call(self, method, params=None):
            return {"value": "nope"}

    with pytest.raises(Exception, match="unexpected shape"):
        scan_solana(OWNER, reader=Weird())


def test_revoke_message_layout():
    msg = build_revoke_message(OWNER, ACCT_A, TOKEN_PROGRAM, BLOCKHASH)
    assert msg[:3] == bytes([1, 0, 1])  # 1 signer, 0 readonly signed, 1 readonly unsigned
    assert msg[3] == 3  # account keys
    assert msg[4:36] == bytes([1] * 32) and msg[36:68] == bytes([4] * 32)
    assert msg[68:100] == b58decode(TOKEN_PROGRAM)
    assert msg[100:132] == bytes([9] * 32)  # recent blockhash
    assert msg[132:] == bytes([1, 2, 2, 1, 0, 1, 5])  # 1 ix: program #2, accounts [1,0], data [5]
    with pytest.raises(ValueError):
        build_revoke_message(OWNER, ACCT_A, TOKEN_PROGRAM, b58encode(bytes(5)))


def approval(**kw):
    base = {
        "chain": "solana",
        "owner": OWNER,
        "token": MINT_A,
        "spender": PROGRAM_DELEGATE,
        "allowance": 5,
        "block_number": 0,
        "tx_hash": "",
        "token_account": ACCT_A,
        "token_program": TOKEN_PROGRAM,
    }
    return Approval(**{**base, **kw})


def test_unsigned_tx_has_an_empty_signature_slot_and_both_encodings():
    tx = build_revoke_tx(approval(), BLOCKHASH)
    raw = base64.b64decode(tx.transaction_base64)
    assert raw[0] == 1 and raw[1:65] == bytes(64)  # one signature, all zero: UNSIGNED
    assert raw[65:] == build_revoke_message(OWNER, ACCT_A, TOKEN_PROGRAM, BLOCKHASH)
    assert b58decode(tx.transaction_base58) == raw
    with pytest.raises(ValueError):
        build_revoke_tx(approval(chain="base"), BLOCKHASH)
    with pytest.raises(ValueError):
        build_revoke_tx(approval(token_account=None), BLOCKHASH)


def test_solana_report_links_to_solscan():
    result = scan_solana(OWNER, reader=wallet(), now=lambda: 1_800_000_000)
    html = render_report(result)
    assert f"https://solscan.io/account/{PROGRAM_DELEGATE}" in html
    assert f"report.html#solana:{OWNER}" in html


class SolanaTransport:
    def __init__(self):
        self.node = wallet()

    def post_json(self, url, payload, *, timeout):
        try:
            result = self.node.call(payload["method"], payload["params"])
        except RpcError as exc:
            return {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "error": {"code": exc.code, "message": str(exc)},
            }
        return {"jsonrpc": "2.0", "id": payload["id"], "result": result}

    def get_json(self, url, *, timeout):
        raise AssertionError("solana scans use no GET endpoints")


def run(args, tmp_path):
    return cli.main([*args, "--db", str(tmp_path / "c.db"), "-q"], transport=SolanaTransport())


def test_cli_scan_json(tmp_path, capsys):
    assert run(["scan", OWNER, "-c", "solana", "--json"], tmp_path) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["chain"] == "solana" and len(data["approvals"]) == 3
    assert isinstance(data["approvals"][0]["approval"]["allowance"], str)


def test_cli_scan_text_and_chains_listing(tmp_path, capsys):
    assert run(["scan", OWNER, "-c", "solana"], tmp_path) == 0
    assert "unlimited" in capsys.readouterr().out
    assert cli.main(["chains"]) == 0
    assert "solana" in capsys.readouterr().out


def test_cli_revoke_builds_unsigned_transactions(tmp_path, capsys):
    assert run(["revoke", OWNER, "-c", "solana", "--min-score", "30", "--json"], tmp_path) == 0
    txs = json.loads(capsys.readouterr().out)
    assert [t["token_account"] for t in txs] == [ACCT_A, ACCT_B]
    assert all(base64.b64decode(t["transaction_base64"])[1:65] == bytes(64) for t in txs)
    assert run(["revoke", OWNER, "-c", "solana", "--spender", WALLET_DELEGATE], tmp_path) == 0
    out = capsys.readouterr().out
    assert "Nothing was signed or sent" in out and "1 unsigned revoke" in out
    assert run(["revoke", OWNER, "-c", "solana", "--min-score", "100"], tmp_path) == 0
    assert "Nothing to revoke" in capsys.readouterr().out


def test_cli_rejects_mismatched_address_types(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        run(["scan", "0x" + "11" * 20, "-c", "solana"], tmp_path)
    assert exc.value.code == 2
    with pytest.raises(SystemExit):
        run(["scan", OWNER, "-c", "base"], tmp_path)
    capsys.readouterr()


def test_rpc_client_works_without_a_chain_id():
    client = RpcClient(["https://sol.example"], SolanaTransport(), min_interval=0)
    assert client.call("getSlot", []) == 4242


def test_solana_is_throttled_below_the_public_rate_limit(monkeypatch):
    import argparse

    from sweepsafe.cli.main import _solana_reader
    from sweepsafe.config.settings import Settings
    from sweepsafe.solana import SOLANA_MIN_INTERVAL, SOLANA_RPCS

    assert SOLANA_MIN_INTERVAL >= 10 / 40  # public cap: 40 calls per method per 10 s
    assert len(SOLANA_RPCS) >= 3
    args = argparse.Namespace(rpc=[])
    monkeypatch.delenv("SWEEPSAFE_REQUEST_INTERVAL", raising=False)
    client = _solana_reader(args, Settings.from_env({}), SolanaTransport())
    assert client.min_interval == SOLANA_MIN_INTERVAL
    monkeypatch.setenv("SWEEPSAFE_REQUEST_INTERVAL", "0")
    client = _solana_reader(
        args, Settings.from_env({"SWEEPSAFE_REQUEST_INTERVAL": "0"}), SolanaTransport()
    )
    assert client.min_interval == 0  # an explicit setting wins
