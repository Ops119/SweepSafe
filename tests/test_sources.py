import pytest

from sweepsafe.chains import TransportError
from sweepsafe.config.chains import BASE, Chain
from sweepsafe.models import Verification
from sweepsafe.sources import (
    BlocklistManager,
    BlockscoutProvider,
    CompositeVerifier,
    SourcifyProvider,
    parse_address_list,
)
from sweepsafe.store import Store

ADDR = "0x" + "ab" * 20
ADDR2 = "0x" + "cd" * 20
ADDR3 = "0x" + "ef" * 20


class MapTransport:
    """get_json returns / raises whatever is registered for a URL substring."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get_json(self, url, *, timeout):
        self.calls.append(url)
        for needle, value in self.routes.items():
            if needle in url:
                if isinstance(value, Exception):
                    raise value
                return value
        raise TransportError("no route", status=404, retriable=False)

    def post_json(self, url, payload, *, timeout):  # pragma: no cover
        raise AssertionError


# -- blocklist parsing -------------------------------------------------------------------------
def test_parse_flat_list_and_objects_and_nested():
    assert parse_address_list([ADDR.upper().replace("0X", "0x"), "nope", 5, None]) == {ADDR}
    assert parse_address_list([{"address": ADDR, "comment": "scam"}, {"address": ADDR2}]) == {
        ADDR,
        ADDR2,
    }
    assert parse_address_list({"blacklist": {"addresses": [ADDR]}, "meta": {"v": 1}}) == {ADDR}


def test_parse_never_lets_allowlists_leak_in():
    data = {"blacklist": [ADDR], "whitelist": [ADDR2], "safe_list": [ADDR3], "Allowed": [ADDR3]}
    assert parse_address_list(data) == {ADDR}


def test_parse_handles_junk():
    assert parse_address_list("0x1234") == set()
    assert parse_address_list(None) == set()
    assert parse_address_list({}) == set()


def test_parse_caps_size(monkeypatch):
    monkeypatch.setattr("sweepsafe.sources.blocklist.MAX_ADDRESSES", 2)
    many = ["0x" + f"{i:040x}" for i in range(10)]
    assert len(parse_address_list(many)) == 2


# -- blocklist manager -------------------------------------------------------------------------
URL_A = "https://lists.example/a.json"
URL_B = "https://lists.example/b.json"


def manager(store, transport, now, urls=(URL_A, URL_B), ttl=100):
    return BlocklistManager(store, transport, urls, ttl=ttl, now=lambda: now[0])


def test_manager_fetches_merges_and_caches():
    store = Store(":memory:")
    transport = MapTransport({"a.json": [ADDR], "b.json": [{"address": ADDR2}]})
    now = [1_000.0]
    blocklist = manager(store, transport, now).load()
    assert ADDR in blocklist and ADDR2.upper().replace("0X", "0x") in blocklist
    assert ADDR3 not in blocklist
    assert blocklist.sources_ok == 2 and blocklist.warnings == []

    transport.calls.clear()
    manager(store, transport, now).load()  # within TTL: served from cache
    assert transport.calls == []

    now[0] += 101  # TTL expired: refetch
    manager(store, transport, now).load()
    assert len(transport.calls) == 2


def test_manager_falls_back_to_stale_cache_then_reports_failures():
    store = Store(":memory:")
    now = [1_000.0]
    manager(store, MapTransport({"a.json": [ADDR], "b.json": [ADDR2]}), now).load()

    now[0] += 500
    down = MapTransport({"a.json": TransportError("offline"), "b.json": TransportError("offline")})
    stale = manager(store, down, now).load()
    assert ADDR in stale and ADDR2 in stale
    assert len(stale.stale_sources) == 2 and any("cached copy" in w for w in stale.warnings)

    fresh_store = Store(":memory:")
    nothing = manager(fresh_store, down, now).load()
    assert nothing.addresses == frozenset()
    assert len(nothing.failed_sources) == 2 and any("unavailable" in w for w in nothing.warnings)


# -- verification providers --------------------------------------------------------------------
def test_sourcify_mapping():
    chain = BASE
    assert (
        SourcifyProvider(MapTransport({"sourcify": {"match": "exact_match"}})).check(chain, ADDR)
        is Verification.VERIFIED
    )
    assert (
        SourcifyProvider(MapTransport({"sourcify": {}})).check(chain, ADDR) is Verification.UNKNOWN
    )
    assert SourcifyProvider(MapTransport({})).check(chain, ADDR) is Verification.UNVERIFIED  # 404
    down = MapTransport({"sourcify": TransportError("500", status=500)})
    assert SourcifyProvider(down).check(chain, ADDR) is Verification.UNKNOWN


def test_sourcify_requires_a_real_match():
    chain = BASE
    check = lambda body: SourcifyProvider(MapTransport({"sourcify": body})).check(chain, ADDR)  # noqa: E731
    assert check({"match": "match"}) is Verification.VERIFIED
    assert check({"match": None, "creationMatch": None}) is Verification.UNVERIFIED
    assert check({"unexpected": 1}) is Verification.UNKNOWN  # not evidence of verification
    assert check([1, 2]) is Verification.UNKNOWN


def test_sourcify_url_contains_chain_id_and_lowercase_address():
    transport = MapTransport({"sourcify": {"match": "match"}})
    SourcifyProvider(transport).check(BASE, "0x" + "AB" * 20)
    assert transport.calls == [f"https://sourcify.dev/server/v2/contract/8453/{ADDR}"]


def test_blockscout_mapping():
    chain = BASE
    assert (
        BlockscoutProvider(MapTransport({"blockscout": {"is_verified": True}})).check(chain, ADDR)
        is Verification.VERIFIED
    )
    assert (
        BlockscoutProvider(MapTransport({"blockscout": {"is_verified": False}})).check(chain, ADDR)
        is Verification.UNVERIFIED
    )
    assert (
        BlockscoutProvider(MapTransport({"blockscout": ["weird"]})).check(chain, ADDR)
        is Verification.UNKNOWN
    )
    assert BlockscoutProvider(MapTransport({})).check(chain, ADDR) is Verification.UNVERIFIED
    assert (
        BlockscoutProvider(MapTransport({"blockscout": TransportError("x")})).check(chain, ADDR)
        is Verification.UNKNOWN
    )
    no_scout = Chain("x", 5, ("https://r.example",), "https://e.example", None)
    assert BlockscoutProvider(MapTransport({})).check(no_scout, ADDR) is Verification.UNKNOWN


class Fixed:
    def __init__(self, value):
        self.value = value
        self.calls = 0
        self.name = "fixed"

    def check(self, chain, address):
        self.calls += 1
        return self.value


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        ([Verification.UNVERIFIED, Verification.VERIFIED], Verification.VERIFIED),
        ([Verification.UNKNOWN, Verification.UNVERIFIED], Verification.UNVERIFIED),
        ([Verification.UNKNOWN, Verification.UNKNOWN], Verification.UNKNOWN),
        ([Verification.UNVERIFIED, Verification.UNKNOWN], Verification.UNVERIFIED),
    ],
)
def test_composite_resolution(answers, expected):
    verifier = CompositeVerifier([Fixed(a) for a in answers])
    assert verifier.check(BASE, ADDR) is expected


def test_composite_short_circuits_on_verified_and_caches():
    first, second = Fixed(Verification.VERIFIED), Fixed(Verification.UNVERIFIED)
    store = Store(":memory:")
    verifier = CompositeVerifier([first, second], store, now=lambda: 1_000)
    assert verifier.check(BASE, ADDR) is Verification.VERIFIED
    assert second.calls == 0
    verifier.check(BASE, ADDR)
    assert first.calls == 1  # second answer came from the cache


def test_composite_never_caches_unknown():
    provider = Fixed(Verification.UNKNOWN)
    verifier = CompositeVerifier([provider], Store(":memory:"), now=lambda: 1_000)
    verifier.check(BASE, ADDR)
    verifier.check(BASE, ADDR)
    assert provider.calls == 2
