from pathlib import Path

import pytest

from sweepsafe.config import CHAINS, Settings, UnknownChainError, get_chain
from sweepsafe.config.settings import DEFAULT_BLOCKLIST_URLS, DEFAULT_PAGES_URL


def test_default_chains_have_unique_ids_and_https_rpcs():
    assert set(CHAINS) == {"ethereum", "base", "arbitrum"}
    assert len({c.chain_id for c in CHAINS.values()}) == 3
    assert (CHAINS["base"].chain_id, CHAINS["arbitrum"].chain_id) == (8453, 42161)
    for chain in CHAINS.values():
        assert len(chain.rpcs) >= 2, "need a fallback provider"
        assert all(url.startswith("https://") for url in chain.rpcs)
        assert chain.reorg_depth > 0


@pytest.mark.parametrize(
    ("alias", "name"),
    [("ETH", "ethereum"), ("mainnet", "ethereum"), (" base ", "base"), ("arb", "arbitrum")],
)
def test_aliases(alias, name):
    assert get_chain(alias).name == name


def test_unknown_chain():
    with pytest.raises(UnknownChainError, match="choose from"):
        get_chain("solana")


def test_rpc_override_keeps_everything_else():
    chain = get_chain("base", ("https://my.rpc",))
    assert chain.rpcs == ("https://my.rpc",)
    assert chain.chain_id == 8453
    assert chain.explorer == CHAINS["base"].explorer
    assert chain.reorg_depth == CHAINS["base"].reorg_depth


def test_settings_defaults():
    settings = Settings.from_env({})
    assert settings.db_path == Path.home() / ".sweepsafe" / "cache.db"
    assert settings.blocklist_urls == DEFAULT_BLOCKLIST_URLS
    assert settings.pages_url == DEFAULT_PAGES_URL
    assert (settings.retries, settings.timeout) == (3, 20.0)


def test_settings_overrides():
    settings = Settings.from_env(
        {
            "SWEEPSAFE_DB": "/tmp/x.db",
            "SWEEPSAFE_REQUEST_INTERVAL": "1.5",
            "SWEEPSAFE_TIMEOUT": "5",
            "SWEEPSAFE_RETRIES": "9",
            "SWEEPSAFE_BACKOFF": "0.25",
            "SWEEPSAFE_BLOCKLIST_URLS": " https://a.example/x.json , https://b.example/y.json ,",
            "SWEEPSAFE_PAGES_URL": "https://me.github.io/sweepsafe/",
        }
    )
    assert settings.db_path == Path("/tmp/x.db")
    assert (settings.request_interval, settings.timeout, settings.retries) == (1.5, 5.0, 9)
    assert settings.backoff == 0.25
    assert settings.blocklist_urls == ("https://a.example/x.json", "https://b.example/y.json")
    assert settings.pages_url == "https://me.github.io/sweepsafe"


def test_rpc_overrides_from_env():
    settings = Settings.from_env({})
    env = {"SWEEPSAFE_RPC_BASE": "https://one.example, https://two.example"}
    assert settings.rpc_overrides("base", env) == ("https://one.example", "https://two.example")
    assert settings.rpc_overrides("ethereum", env) == ()


def test_default_blocklists_are_address_based_https_urls():
    assert all(u.startswith("https://raw.githubusercontent.com/") for u in DEFAULT_BLOCKLIST_URLS)
