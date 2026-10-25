from fakes import (
    CONTRACT_CODE,
    OWNER,
    SPENDER_1,
    SPENDER_2,
    SPENDER_3,
    TOKEN_A,
    TOKEN_B,
    FakeNode,
    NodeTransport,
    make_log,
)
from scenarios import BLOCKLIST_URL, NOW, wallet_node
from sweepsafe.chains import RpcError, RpcUnavailableError, TransportError
from sweepsafe.config import Settings, get_chain
from sweepsafe.models import Verification
from sweepsafe.service import classify_spender, is_contract_code, open_dependencies, scan_wallet
from sweepsafe.sources import Blocklist
from sweepsafe.store import Store

ETH = get_chain("ethereum")


class MapVerifier:
    def __init__(self, mapping, default=Verification.UNVERIFIED):
        self.mapping = mapping
        self.default = default
        self.calls = []

    def check(self, chain, address):
        self.calls.append(address)
        return self.mapping.get(address, self.default)


def run(node=None, verifier=None, blocklist=None, **kwargs):
    node = node or wallet_node()
    with Store(":memory:") as store:
        return scan_wallet(
            OWNER.upper().replace("0X", "0x"),
            ETH,
            reader=node,
            store=store,
            verifier=verifier or MapVerifier({}),
            blocklist=blocklist,
            now=lambda: NOW,
            **kwargs,
        )


def test_end_to_end_scoring_and_ordering():
    result = run(blocklist=Blocklist(addresses=frozenset({SPENDER_3})))
    assert result.owner == OWNER
    assert result.chain == "ethereum" and result.chain_id == 1
    assert result.scanned_to_block == 2_000
    assert result.generated_at == NOW
    summary = [(i.approval.spender, i.risk.score, i.risk.level) for i in result.approvals]
    assert summary == [
        (SPENDER_3, 100, "critical"),
        (SPENDER_1, 70, "high"),
        (SPENDER_2, 30, "medium"),
    ]
    critical = result.approvals[0]
    assert critical.approval.blocklisted is True
    assert "blocklist" in critical.explanation
    assert result.approvals[1].approval.token_symbol == "USDC"
    assert result.approvals[1].explanation.startswith("USDC: unlimited allowance for")
    assert result.warnings == []


def test_eoa_spender_skips_verification_lookup():
    verifier = MapVerifier({})
    run(verifier=verifier)
    assert SPENDER_2 not in verifier.calls
    assert sorted(verifier.calls) == sorted([SPENDER_1, SPENDER_3])


def test_verified_contract_is_not_flagged():
    verifier = MapVerifier({SPENDER_1: Verification.VERIFIED, SPENDER_3: Verification.VERIFIED})
    result = run(verifier=verifier)
    by_spender = {i.approval.spender: i for i in result.approvals}
    assert [f.rule_id for f in by_spender[SPENDER_1].risk.findings] == [
        "unlimited_allowance",
        "stale_approval",
    ]
    assert by_spender[SPENDER_3].risk.findings == []


def test_unknown_contractness_adds_warning_and_skips_dependent_rules():
    class Flaky(FakeNode):
        def get_code(self, address):
            raise RpcError(-32000, "header not found")

    node = wallet_node()
    flaky = Flaky(
        head=node.head,
        logs=node.logs,
        allowances=node.allowances,
        tokens=node.tokens,
        timestamps=node.timestamps,
    )
    result = run(node=flaky)
    assert sum("Could not tell whether spender" in w for w in result.warnings) == 3
    assert all(i.approval.spender_is_contract is None for i in result.approvals)
    assert all(
        "spender_is_eoa" not in [f.rule_id for f in i.risk.findings] for i in result.approvals
    )


def test_blocklist_warnings_are_surfaced():
    blocklist = Blocklist(failed_sources=["https://lists.example/x.json"])
    result = run(blocklist=blocklist)
    assert any("Blocklist source unavailable" in w for w in result.warnings)


def test_no_approvals_gives_empty_result():
    result = run(node=FakeNode(head=50))
    assert result.approvals == [] and result.scanned_to_block == 50


def test_same_spender_is_classified_once():
    node = wallet_node()
    node.logs.append(make_log(TOKEN_B, OWNER, SPENDER_1, 3, 400))
    node.allowances[(TOKEN_B, SPENDER_1)] = 3
    node.timestamps[400] = NOW
    calls = []
    original = node.get_code
    node.get_code = lambda a: (calls.append(a), original(a))[1]
    run(node=node)
    assert calls.count(SPENDER_1) == 1


# -- helpers ---------------------------------------------------------------------------------
def test_is_contract_code_variants():
    assert not is_contract_code("0x")
    assert not is_contract_code("0x0")
    assert not is_contract_code("")
    assert is_contract_code(CONTRACT_CODE)
    assert not is_contract_code("0xef0100" + "ab" * 20)  # EIP-7702 delegated wallet
    assert is_contract_code("0xef0100" + "ab" * 21)  # wrong length: treat as real code


def test_classify_spender_returns_none_on_failures():
    for exc in (RpcError(-32000, "x"), RpcUnavailableError("down"), TransportError("net")):

        class Down(FakeNode):
            def get_code(self, address, _exc=exc):
                raise _exc

        assert classify_spender(Down(), SPENDER_1) is None
    assert classify_spender(FakeNode(codes={SPENDER_1: CONTRACT_CODE}), SPENDER_1) is True
    assert classify_spender(FakeNode(), SPENDER_1) is False


# -- full wiring through the real RPC client, store and verifier -------------------------------
def test_open_dependencies_end_to_end(tmp_path):
    node = wallet_node()
    transport = NodeTransport(
        node,
        chain_id=1,
        blocklists={BLOCKLIST_URL: [SPENDER_3]},
        verified={SPENDER_1},
    )
    settings = Settings.from_env(
        {
            "SWEEPSAFE_DB": str(tmp_path / "cache.db"),
            "SWEEPSAFE_BLOCKLIST_URLS": BLOCKLIST_URL,
            "SWEEPSAFE_REQUEST_INTERVAL": "0",
        }
    )
    with open_dependencies("ethereum", settings, transport=transport) as deps:
        result = scan_wallet(
            OWNER,
            deps.chain,
            reader=deps.reader,
            store=deps.store,
            verifier=deps.verifier,
            blocklist=deps.blocklist,
            now=lambda: NOW,
        )
    by_spender = {i.approval.spender: i for i in result.approvals}
    assert by_spender[SPENDER_3].risk.level == "critical"
    assert by_spender[SPENDER_1].approval.verification is Verification.VERIFIED
    assert by_spender[SPENDER_2].approval.spender_is_contract is False
    assert (tmp_path / "cache.db").exists()
    assert TOKEN_A in {i.approval.token for i in result.approvals}


def test_open_dependencies_can_skip_blocklist(tmp_path):
    settings = Settings.from_env({"SWEEPSAFE_DB": str(tmp_path / "c.db")})
    transport = NodeTransport(FakeNode())
    with open_dependencies(
        "ethereum", settings, transport=transport, refresh_blocklist=False
    ) as deps:
        assert deps.blocklist.addresses == frozenset()
    assert transport.gets == []
