"""Command line interface: ``sweepsafe scan | revoke | report | chains``."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from sweepsafe import __version__
from sweepsafe.abi import AbiError, normalize_address
from sweepsafe.chains.rpc import ChainMismatchError, RpcError, RpcUnavailableError
from sweepsafe.chains.transport import Transport, TransportError
from sweepsafe.config.chains import CHAINS, UnknownChainError
from sweepsafe.config.settings import Settings
from sweepsafe.models import ScanResult, ScoredApproval
from sweepsafe.report import render_report
from sweepsafe.revoker import build_revoke_txs, select_for_revoke
from sweepsafe.scanner import ScanError
from sweepsafe.service import Dependencies, open_dependencies, scan_wallet

EXPECTED_ERRORS = (
    UnknownChainError,
    ScanError,
    RpcError,
    RpcUnavailableError,
    ChainMismatchError,
    TransportError,
    AbiError,
    OSError,
)

_COLORS = {"critical": "31", "high": "33", "medium": "93", "low": "32"}


def _address(value: str) -> str:
    try:
        return normalize_address(value)
    except AbiError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sweepsafe",
        description="Find and revoke risky token approvals. Free, open source, non-custodial.",
        epilog="SweepSafe never asks for a private key or seed phrase.",
    )
    parser.add_argument("--version", action="version", version=f"sweepsafe {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("address", type=_address, help="wallet address (0x...)")
        p.add_argument("-c", "--chain", default="ethereum", help=f"one of: {', '.join(CHAINS)}")
        p.add_argument(
            "--rpc",
            action="append",
            default=[],
            metavar="URL",
            help="use this RPC URL instead of the built-in public ones (repeatable)",
        )
        p.add_argument(
            "--db", metavar="PATH", help="cache database (default ~/.sweepsafe/cache.db)"
        )
        p.add_argument(
            "--from-block",
            type=int,
            metavar="N",
            help="skip history before block N (faster, but may miss old approvals)",
        )
        p.add_argument(
            "--reset", action="store_true", help="discard cached scan data for this wallet"
        )
        p.add_argument("-q", "--quiet", action="store_true", help="no progress output")

    scan = sub.add_parser("scan", help="list active approvals with risk scores")
    common(scan)
    scan.add_argument(
        "--min-score", type=int, default=0, help="only show approvals at or above this score"
    )
    scan.add_argument("--json", action="store_true", help="machine-readable output")

    revoke = sub.add_parser("revoke", help="build UNSIGNED revoke transactions (you sign them)")
    common(revoke)
    revoke.add_argument("--min-score", type=int, help="revoke approvals at or above this score")
    revoke.add_argument("--token", type=_address, help="only this token contract")
    revoke.add_argument("--spender", type=_address, help="only this spender")
    revoke.add_argument("--all", action="store_true", help="select every active approval")
    revoke.add_argument("--json", action="store_true", help="machine-readable output")

    report = sub.add_parser("report", help="write a shareable static HTML report")
    common(report)
    report.add_argument(
        "-o", "--out", default="report.html", help="output file (default report.html)"
    )

    sub.add_parser("chains", help="list supported chains")
    return parser


# -- helpers -------------------------------------------------------------------------------
def _paint(text: str, level: str, enabled: bool) -> str:
    return f"\033[{_COLORS.get(level, '0')}m{text}\033[0m" if enabled else text


def _progress(quiet: bool) -> Callable[[int, int], None] | None:
    if quiet:
        return None
    state = {"last": -1}

    def report(done: int, total: int) -> None:
        pct = 100 if total <= 0 else min(100, int(done * 100 / total))
        if pct != state["last"] and (pct % 5 == 0 or pct == 100):
            state["last"] = pct
            print(f"scanning logs... {pct}% (block {done}/{total})", file=sys.stderr)

    return report


def _run_scan(
    args: argparse.Namespace, transport: Transport | None
) -> tuple[ScanResult, Dependencies]:
    settings = Settings.from_env()
    if args.db:
        settings = dataclasses.replace(settings, db_path=Path(args.db))
    deps = open_dependencies(args.chain, settings, rpc_urls=tuple(args.rpc), transport=transport)
    try:
        result = scan_wallet(
            args.address,
            deps.chain,
            reader=deps.reader,
            store=deps.store,
            verifier=deps.verifier,
            blocklist=deps.blocklist,
            from_block=args.from_block,
            reset=args.reset,
            progress=_progress(args.quiet),
        )
    except BaseException:
        deps.store.close()
        raise
    return result, deps


def _print_scan(result: ScanResult, items: list[ScoredApproval], color: bool) -> None:
    print(f"{result.owner} on {result.chain} (scanned to block {result.scanned_to_block})")
    if not items:
        print("No active approvals match.")
    for item in items:
        a = item.approval
        head = f"[{item.risk.level.upper():8} {item.risk.score:3}]"
        print(_paint(head, item.risk.level, color) + " " + item.explanation.splitlines()[0])
        for line in item.explanation.splitlines()[1:]:
            print(f"    {line}")
        print(f"    token {a.token}\n    spender {a.spender}")
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)


# -- commands ------------------------------------------------------------------------------
def _cmd_scan(args: argparse.Namespace, transport: Transport | None) -> int:
    result, deps = _run_scan(args, transport)
    deps.store.close()
    items = [i for i in result.approvals if i.risk.score >= args.min_score]
    if args.json:
        shown = result.model_copy(update={"approvals": items})
        print(shown.model_dump_json(indent=2))
    else:
        _print_scan(result, items, sys.stdout.isatty() and "NO_COLOR" not in os.environ)
    return 0


def _cmd_revoke(args: argparse.Namespace, transport: Transport | None) -> int:
    if not (args.all or args.min_score is not None or args.token or args.spender):
        print(
            "error: choose what to revoke: --min-score N, --token ADDR, --spender ADDR or --all",
            file=sys.stderr,
        )
        return 2
    result, deps = _run_scan(args, transport)
    deps.store.close()
    selected = select_for_revoke(
        result.approvals, min_score=args.min_score or 0, token=args.token, spender=args.spender
    )
    txs = build_revoke_txs(deps.chain, selected)
    if args.json:
        print(
            json.dumps(
                [{**tx.as_wallet_request(), "description": tx.description} for tx in txs], indent=2
            )
        )
        return 0
    if not txs:
        print("Nothing to revoke for that selection.")
        return 0
    print(f"{len(txs)} unsigned revoke transaction(s) for {result.owner} on {result.chain}.")
    print(
        "Nothing was signed or sent. Review each one, then send it from YOUR wallet\n"
        f"(it must be sent from {result.owner}).\n"
    )
    for number, tx in enumerate(txs, 1):
        print(
            f"#{number} {tx.description}\n"
            f"  chainId {tx.chain_id}\n  to      {tx.to}\n  data    {tx.data}\n"
        )
    return 0


def _cmd_report(args: argparse.Namespace, transport: Transport | None) -> int:
    result, deps = _run_scan(args, transport)
    deps.store.close()
    settings = Settings.from_env()
    html = render_report(result, pages_url=settings.pages_url)
    out = Path(args.out)
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out} ({len(result.approvals)} approval(s))")
    return 0


def _cmd_chains(_args: argparse.Namespace, _transport: Transport | None) -> int:
    for chain in CHAINS.values():
        print(f"{chain.name:10} id {chain.chain_id:<6} {len(chain.rpcs)} public RPCs")
    return 0


_COMMANDS = {"scan": _cmd_scan, "revoke": _cmd_revoke, "report": _cmd_report, "chains": _cmd_chains}


def main(argv: Sequence[str] | None = None, *, transport: Transport | None = None) -> int:
    """Entry point. ``transport`` is injectable so tests never touch the network."""
    args = build_parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args, transport)
    except KeyboardInterrupt:
        print("\ninterrupted; progress is saved and the next run resumes.", file=sys.stderr)
        return 130
    except EXPECTED_ERRORS as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
