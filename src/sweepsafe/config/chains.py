"""Chain registry. Public RPC endpoints are free and keyless; users can override them via env."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Chain:
    name: str
    chain_id: int
    rpcs: tuple[str, ...]
    explorer: str
    blockscout: str | None = None
    reorg_depth: int = 64  # blocks re-scanned on resume so shallow reorgs cannot leave stale logs
    start_block: int = 0


ETHEREUM = Chain(
    name="ethereum",
    chain_id=1,
    rpcs=(
        "https://ethereum-rpc.publicnode.com",
        "https://eth.llamarpc.com",
        "https://cloudflare-eth.com",
    ),
    explorer="https://etherscan.io",
    blockscout="https://eth.blockscout.com",
    reorg_depth=64,
)

BASE = Chain(
    name="base",
    chain_id=8453,
    rpcs=(
        "https://base-rpc.publicnode.com",
        "https://mainnet.base.org",
        "https://base.llamarpc.com",
    ),
    explorer="https://basescan.org",
    blockscout="https://base.blockscout.com",
    reorg_depth=256,
)

ARBITRUM = Chain(
    name="arbitrum",
    chain_id=42161,
    rpcs=(
        "https://arbitrum-one-rpc.publicnode.com",
        "https://arb1.arbitrum.io/rpc",
        "https://arbitrum.llamarpc.com",
    ),
    explorer="https://arbiscan.io",
    blockscout="https://arbitrum.blockscout.com",
    reorg_depth=1000,
)

CHAINS: dict[str, Chain] = {c.name: c for c in (ETHEREUM, BASE, ARBITRUM)}

_ALIASES = {
    "eth": "ethereum",
    "mainnet": "ethereum",
    "arb": "arbitrum",
    "arbitrum-one": "arbitrum",
}


class UnknownChainError(ValueError):
    pass


def get_chain(name: str, rpc_overrides: tuple[str, ...] = ()) -> Chain:
    """Look up a chain by name or alias; optionally replace its RPC list."""
    key = _ALIASES.get(name.strip().lower(), name.strip().lower())
    chain = CHAINS.get(key)
    if chain is None:
        raise UnknownChainError(f"unknown chain {name!r}; choose from: {', '.join(sorted(CHAINS))}")
    if rpc_overrides:
        return Chain(
            name=chain.name,
            chain_id=chain.chain_id,
            rpcs=tuple(rpc_overrides),
            explorer=chain.explorer,
            blockscout=chain.blockscout,
            reorg_depth=chain.reorg_depth,
            start_block=chain.start_block,
        )
    return chain
