# SweepSafe

[![CI](https://github.com/Ops119/SweepSafe/actions/workflows/ci.yml/badge.svg)](https://github.com/Ops119/SweepSafe/actions/workflows/ci.yml)
[![Live demo](https://img.shields.io/badge/live-demo-2457d6)](https://ops119.github.io/SweepSafe/report.html)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**Find and revoke risky token approvals. Free. Non-custodial.**

SweepSafe scans an Ethereum, Base or Arbitrum wallet for ERC-20 approvals, scores each one
for risk, explains it in plain English, and builds the unsigned `approve(spender, 0)`
transaction that removes it. It uses public RPCs and open scam lists, so it costs nothing to run.

- **Read-only by default.** It never asks for a private key or seed phrase and never signs for you.
- **No backend, accounts or tracking.** The CLI runs locally; the web viewer runs entirely in your browser.
- **Same rules everywhere.** The CLI and the viewer score from one shared `rules.json`.

## Try it

Web (no install): <https://ops119.github.io/SweepSafe/report.html>. Share a result with
`report.html#base:0xYourAddress`.

CLI:

```bash
pipx install git+https://github.com/Ops119/SweepSafe
sweepsafe scan 0xYourAddress --chain base
sweepsafe report 0xYourAddress --chain base -o report.html
sweepsafe revoke 0xYourAddress --chain base --min-score 50   # prints unsigned transactions
```

`revoke` requires `--min-score`, `--token`, `--spender` or `--all`. Exit codes: 0 ok, 1 findings
or errors, 2 usage error, 130 interrupted.

## How scoring works

| Rule | Points |
| --- | --- |
| Spender on a scam blocklist | 100 |
| Unlimited allowance | 35 |
| Spender is a plain wallet (EOA) | 30 |
| Unverified contract | 20 |
| Approval older than 180 days | 15 |
| Verification unknown | 5 |

The total is capped at 100. Critical ≥ 75, high ≥ 50, medium ≥ 25, otherwise low. Rules are in
[`rules.json`](src/sweepsafe/data/rules.json). A low score is not a guarantee of safety.

## How it works

Approval events are read from public RPCs in adaptive chunks and cached for resuming; the live
allowance is then read with `eth_call`, because an old event can be stale. Spenders are
classified with `eth_getCode` and checked against Sourcify and Blockscout and open address lists.

## Stack note

The spec called for web3.py, Typer and httpx. The build sandbox could not install them, so the
CLI uses the standard library (`urllib`, `argparse`, `sqlite3`) plus `pydantic`, behind small
`Transport`, `ChainReader` and `VerificationProvider` interfaces that make swapping them in easy.

## Limitations

- Public RPCs can be slow or rate-limited; first scans of old wallets may take minutes.
- A provider that silently truncates logs can hide approvals.
- ERC-20 only: no NFT approvals and no Permit2.
- Addresses you type are not EIP-55 checksum-validated.
- Blocklists and verification services are third parties and can be wrong or offline.
- The Pages demo calls those services from your browser, so it needs them to allow CORS.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## Enable the web viewer

Repository Settings → Pages → Source: **GitHub Actions**, then push to `main`.

MIT licensed.
