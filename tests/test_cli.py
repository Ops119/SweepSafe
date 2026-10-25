import json

import pytest

from fakes import OWNER, SPENDER_1, SPENDER_2, SPENDER_3, TOKEN_A, TOKEN_B, FakeNode, NodeTransport
from scenarios import BLOCKLIST_URL, wallet_node
from sweepsafe import cli
from sweepsafe.chains import TransportError


@pytest.fixture
def transport():
    return NodeTransport(
        wallet_node(),
        chain_id=8453,
        blocklists={BLOCKLIST_URL: [SPENDER_3]},
        verified=set(),
    )


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SWEEPSAFE_BLOCKLIST_URLS", BLOCKLIST_URL)
    monkeypatch.setenv("NO_COLOR", "1")


def run(args, transport, tmp_path):
    return cli.main([*args, "--db", str(tmp_path / "c.db"), "-q"], transport=transport)


def test_scan_json(transport, tmp_path, capsys):
    assert run(["scan", OWNER, "--chain", "base", "--json"], transport, tmp_path) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["chain"] == "base" and data["chain_id"] == 8453
    scores = [a["risk"]["score"] for a in data["approvals"]]
    assert scores == sorted(scores, reverse=True) and scores[0] == 100
    assert isinstance(data["approvals"][0]["approval"]["allowance"], str)  # uint256 as string


def test_scan_min_score_filters(transport, tmp_path, capsys):
    run(["scan", OWNER, "-c", "base", "--json", "--min-score", "60"], transport, tmp_path)
    data = json.loads(capsys.readouterr().out)
    assert [a["risk"]["level"] for a in data["approvals"]] == ["critical", "high"]


def test_scan_human_output(transport, tmp_path, capsys):
    assert run(["scan", OWNER, "-c", "base"], transport, tmp_path) == 0
    out = capsys.readouterr().out
    assert "[CRITICAL" in out and "[HIGH" in out and "[MEDIUM" in out
    assert "USDC: unlimited allowance" in out
    assert f"spender {SPENDER_3}" in out
    assert "\033[" not in out  # NO_COLOR respected / not a tty


def test_scan_prints_progress_unless_quiet(transport, tmp_path, capsys):
    cli.main(["scan", OWNER, "-c", "base", "--db", str(tmp_path / "c.db")], transport=transport)
    assert "scanning logs" in capsys.readouterr().err


def test_revoke_requires_an_explicit_selection(transport, tmp_path, capsys):
    assert run(["revoke", OWNER, "-c", "base"], transport, tmp_path) == 2
    assert "choose what to revoke" in capsys.readouterr().err
    assert transport.gets == []  # refused before touching the network


def test_revoke_json_builds_unsigned_transactions(transport, tmp_path, capsys):
    assert (
        run(["revoke", OWNER, "-c", "base", "--min-score", "50", "--json"], transport, tmp_path)
        == 0
    )
    txs = json.loads(capsys.readouterr().out)
    assert len(txs) == 2
    assert {t["to"] for t in txs} == {TOKEN_A, TOKEN_B}
    for tx in txs:
        assert tx["data"].startswith("0x095ea7b3") and tx["data"].endswith("0" * 64)
        assert tx["chainId"] == "0x2105" and tx["value"] == "0x0"
        assert "from" not in tx and "privateKey" not in json.dumps(tx)


def test_revoke_by_token_and_spender(transport, tmp_path, capsys):
    run(
        ["revoke", OWNER, "-c", "base", "--token", TOKEN_A, "--spender", SPENDER_2, "--json"],
        transport,
        tmp_path,
    )
    (tx,) = json.loads(capsys.readouterr().out)
    assert tx["to"] == TOKEN_A and SPENDER_2[2:] in tx["data"]


def test_revoke_human_output_states_nothing_was_signed(transport, tmp_path, capsys):
    assert run(["revoke", OWNER, "-c", "base", "--all"], transport, tmp_path) == 0
    out = capsys.readouterr().out
    assert "3 unsigned revoke transaction(s)" in out
    assert "Nothing was signed or sent" in out
    assert f"must be sent from {OWNER}" in out


def test_revoke_with_no_match(transport, tmp_path, capsys):
    assert run(["revoke", OWNER, "-c", "base", "--min-score", "101"], transport, tmp_path) == 0
    assert "Nothing to revoke" in capsys.readouterr().out


def test_report_command_writes_escaped_html(transport, tmp_path, capsys):
    out_file = tmp_path / "r.html"
    assert run(["report", OWNER, "-c", "base", "-o", str(out_file)], transport, tmp_path) == 0
    html = out_file.read_text(encoding="utf-8")
    assert "SweepSafe report" in html and "<script" not in html.lower()
    assert "wrote" in capsys.readouterr().out


def test_chains_command(capsys):
    assert cli.main(["chains"]) == 0
    out = capsys.readouterr().out
    assert "ethereum" in out and "base" in out and "arbitrum" in out


def test_invalid_address_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as info:
        cli.main(["scan", "0x1234"])
    assert info.value.code == 2
    assert "invalid address" in capsys.readouterr().err


def test_unknown_chain_is_a_clean_error(transport, tmp_path, capsys):
    assert run(["scan", OWNER, "-c", "solana"], transport, tmp_path) == 1
    assert "unknown chain" in capsys.readouterr().err


def test_network_failure_is_a_clean_error(tmp_path, capsys):
    class Down:
        def post_json(self, url, payload, *, timeout):
            raise TransportError("offline")

        def get_json(self, url, *, timeout):
            raise TransportError("offline")

    code = cli.main(
        ["scan", OWNER, "-c", "base", "--db", str(tmp_path / "c.db"), "-q"], transport=Down()
    )
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_insecure_rpc_override_is_refused(transport, tmp_path, capsys):
    code = run(["scan", OWNER, "-c", "base", "--rpc", "http://evil.example"], transport, tmp_path)
    assert code == 1 and "refusing non-HTTPS" in capsys.readouterr().err


def test_rpc_override_is_used(tmp_path):
    node = FakeNode(head=10)
    transport = NodeTransport(node, chain_id=8453)
    used = []
    original = transport.post_json
    transport.post_json = lambda url, payload, *, timeout: (
        used.append(url),
        original(url, payload, timeout=timeout),
    )[1]
    cli.main(
        [
            "scan",
            OWNER,
            "-c",
            "base",
            "--rpc",
            "https://my.node.example",
            "--db",
            str(tmp_path / "c.db"),
            "-q",
            "--json",
        ],
        transport=transport,
    )
    assert set(used) == {"https://my.node.example"}


def test_keyboard_interrupt_exits_130(monkeypatch, capsys):
    def interrupted(args, transport):
        raise KeyboardInterrupt

    monkeypatch.setitem(cli.main.__globals__["_COMMANDS"], "scan", interrupted)
    assert cli.main(["scan", OWNER]) == 130
    assert "progress is saved" in capsys.readouterr().err


def test_second_run_resumes_from_cache(transport, tmp_path):
    run(["scan", OWNER, "-c", "base", "--json"], transport, tmp_path)
    node = transport.node
    node.log_requests.clear()
    node.head += 50
    run(["scan", OWNER, "-c", "base", "--json"], transport, tmp_path)
    assert node.log_requests[0][0] > 1_000  # only the tail, never from genesis


def test_reset_flag_rescans_from_genesis(transport, tmp_path):
    run(["scan", OWNER, "-c", "base", "--json"], transport, tmp_path)
    transport.node.log_requests.clear()
    run(["scan", OWNER, "-c", "base", "--json", "--reset"], transport, tmp_path)
    assert transport.node.log_requests[0][0] == 0


def test_python_dash_m_entry_point_exists():
    import importlib.util

    assert importlib.util.find_spec("sweepsafe.__main__") is not None
    assert SPENDER_1  # keep the shared fixture import honest
