"""A shared three-approval wallet used by the service, report and CLI tests."""

from __future__ import annotations

from fakes import (
    CONTRACT_CODE,
    MAX_UINT,
    OWNER,
    SPENDER_1,
    SPENDER_2,
    SPENDER_3,
    TOKEN_A,
    TOKEN_B,
    FakeNode,
    make_log,
)

NOW = 1_800_000_000
DAY = 86_400

BLOCKLIST_URL = "https://lists.example/scams.json"


def wallet_node() -> FakeNode:
    """
    * TOKEN_A -> SPENDER_1: unlimited, unverified contract, 400 days old   -> high (70)
    * TOKEN_A -> SPENDER_2: 500 USDC to a plain wallet (EOA)               -> medium (30)
    * TOKEN_B -> SPENDER_3: tiny amount to a blocklisted unverified contract -> critical (100)
    """
    return FakeNode(
        head=2_000,
        logs=[
            make_log(TOKEN_A, OWNER, SPENDER_1, MAX_UINT, 100),
            make_log(TOKEN_A, OWNER, SPENDER_2, 500_000_000, 200),
            make_log(TOKEN_B, OWNER, SPENDER_3, 7, 300),
        ],
        allowances={
            (TOKEN_A, SPENDER_1): MAX_UINT,
            (TOKEN_A, SPENDER_2): 500_000_000,
            (TOKEN_B, SPENDER_3): 7,
        },
        tokens={TOKEN_A: ("USDC", 6), TOKEN_B: ("WETH", 18)},
        codes={SPENDER_1: CONTRACT_CODE, SPENDER_3: CONTRACT_CODE},
        timestamps={
            100: NOW - 400 * DAY,
            200: NOW - 5 * DAY,
            300: NOW - 1 * DAY,
        },
    )
