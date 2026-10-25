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
from sweepsafe.chains.rpc import ChainMismatchError, RpcClient, RpcError, RpcUnavailableError
from sweepsafe.chains.transport import Transport, TransportError, UrllibTransport
from sweepsafe.config.chains import CHAINS, UnknownChainError
from sweepsafe.config.settings import Settings
from sweepsafe.models import ScanResult, ScoredApproval
from sweepsafe.report import render_report
from sweepsafe.revoker import build_revoke_txs, select_for_revoke
from sweepsafe.scanner import ScanError
from sweepsafe.service import Dependencies, open_dependencies, scan_wallet
from sweepsafe.solana import SOLANA_MIN_INTERVAL, SOLANA_RPCS, is_solana_address, scan_solana
from sweepsafe.solana import build_revoke_tx as build_solana_revoke

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
    """Accept an EVM (0x...) or Solana (base58) address; the chain decides which is valid."""
    if is_solana_address(value):
        return value
    try:
        return normalize_address(value)
    except AbiError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _is_solana(chain: str) -> bool:
    return chain.strip().lower() == "solana"


def _check_address_for_chain(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    for name in ("address", "token", "spender"):
        value = getattr(args, name, None)
        if not value:
            continue
        if _is_solana(args.chain) != is_solana_address(value):
            parser.error(
                f"{name} {value!r} is not a valid {'Solana' if _is_solana(args.chain) else 'EVM'}"
                f" address for chain {args.chain!r}"
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sweepsafe",
        description="Find and revoke risky token approvals. Free, open source, non-custodial.",
        epilog="SweepSafe never asks for a private key or seed phrase.",
    )
    parser.add_argument("--version", action="version", version=f"sweepsafe {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("address", type=_address, help="wallet address (0x... or Solana base58)")
        p.add_argument(
            "-c", "--chain", default="ethereum", help=f"one of: {', '.join([*CHAINS, 'solana'])}"
        )
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
    if _is_solana(args.chain):
        return _run_solana_scan(args, settings, transport)
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


class _NoStore:
    def close(self) -> None:
        return None


@dataclasses.dataclass
class _SolanaDeps:
    reader: RpcClient
    chain: None = None
    store: _NoStore = dataclasses.field(default_factory=_NoStore)


def _solana_reader(
    args: argparse.Namespace, settings: Settings, transport: Transport | None
) -> RpcClient:
    urls = tuple(args.rpc) or settings.rpc_overrides("solana") or SOLANA_RPCS
    return RpcClient(
        urls,
        transport or UrllibTransport(),
        retries=settings.retries,
        backoff=settings.backoff,
        # Slower than EVM by default; an explicit SWEEPSAFE_REQUEST_INTERVAL still wins.
        min_interval=(
            settings.request_interval
            if "SWEEPSAFE_REQUEST_INTERVAL" in os.environ
            else max(settings.request_interval, SOLANA_MIN_INTERVAL)
        ),
        timeout=settings.timeout,
    )


def _run_solana_scan(
    args: argparse.Namespace, settings: Settings, transport: Transport | None
) -> tuple[ScanResult, _SolanaDeps]:
    for flag, used in (("--from-block", args.from_block is not None), ("--reset", args.reset)):
        if used:
            print(
                f"note: {flag} has no effect on Solana scans (nothing is cached).", file=sys.stderr
            )
    reader = _solana_reader(args, settings, transport)
    return scan_solana(args.address, reader=reader), _SolanaDeps(reader)


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
    if _is_solana(args.chain):
        return _revoke_solana(args, result, deps)
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


def _revoke_solana(args: argparse.Namespace, result: ScanResult, deps: _SolanaDeps) -> int:
    chosen = [
        i
        for i in result.approvals
        if i.risk.score >= (args.min_score or 0)
        and (not args.token or i.approval.token == args.token)
        and (not args.spender or i.approval.spender == args.spender)
    ]
    if not chosen:
        print("Nothing to revoke for that selection.")
        return 0
    blockhash = deps.reader.call("getLatestBlockhash", [{"commitment": "confirmed"}])["value"][
        "blockhash"
    ]
    txs = [build_solana_revoke(i.approval, blockhash) for i in chosen]
    if args.json:
        print(json.dumps([tx.model_dump() for tx in txs], indent=2))
        return 0
    print(f"{len(txs)} unsigned revoke transaction(s) for {result.owner} on solana.")
    print(
        "Nothing was signed or sent. Each transaction expires in about a minute, so sign\n"
        "and send it promptly from YOUR wallet (the owner above). Re-run for fresh ones.\n"
    )
    for number, tx in enumerate(txs, 1):
        print(f"#{number} {tx.description}\n  base64  {tx.transaction_base64}\n")
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
    print(f"{'solana':10} SPL token delegations, {len(SOLANA_RPCS)} public RPCs")
    return 0


_COMMANDS = {"scan": _cmd_scan, "revoke": _cmd_revoke, "report": _cmd_report, "chains": _cmd_chains}


def main(argv: Sequence[str] | None = None, *, transport: Transport | None = None) -> int:
    """Entry point. ``transport`` is injectable so tests never touch the network."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "chains":
        _check_address_for_chain(parser, args)
    try:
        return _COMMANDS[args.command](args, transport)
    except KeyboardInterrupt:
        print("\ninterrupted; progress is saved and the next run resumes.", file=sys.stderr)
        return 130
    except EXPECTED_ERRORS as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
