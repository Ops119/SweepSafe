# SweepSafe

[![CI](https://github.com/Ops119/SweepSafe/actions/workflows/ci.yml/badge.svg)](https://github.com/Ops119/SweepSafe/actions/workflows/ci.yml)
[![Live demo](https://img.shields.io/badge/live-demo-2457d6)](https://ops119.github.io/SweepSafe/report.html)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**Find and revoke risky token approvals. Free. Non-custodial.**

SweepSafe scans a wallet on Ethereum, Base, Arbitrum, Optimism, Polygon, BNB Chain, Avalanche, Linea or Robinhood Chain for ERC-20 approvals, and a Solana
wallet for SPL token delegations. It scores each one for risk, explains it in plain English, and
builds the unsigned transaction that removes it (`approve(spender, 0)` on EVM, `Revoke` on Solana). It uses public RPCs and open scam lists, so it costs nothing to run.

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

`revoke` requires `--min-score`, `--token`, `--spender` or `--all`. Exit codes: 0 success (even when
approvals are found), 1 error, 2 usage error, 130 interrupted.

## Solana

`sweepsafe scan <address> -c solana` lists SPL token *delegations*, which are Solana's equivalent
of approvals: each token account can name one delegate and an amount. Both the Token and
Token-2022 programs are covered. `revoke -c solana` prints unsigned base64 transactions that you
sign and send from your own wallet; they expire in about a minute, so re-run for fresh ones. The
web scanner does the same through Phantom-style wallets.

Differences from EVM: there is no public scam-address list or source verification for Solana,
so those checks are skipped (a warning says so), and delegations have no timestamp, so the
stale-approval rule does not apply. A delegated amount of 2^63 or more counts as unlimited.

## Wallets

The web scanner lists every installed wallet and lets you choose: EVM wallets through EIP-6963
(MetaMask, Trust Wallet, Phantom, Rabby, Coinbase Wallet and others), Solana wallets through
Wallet Standard (Phantom, Solflare, Backpack and others), with a fallback to older injected
wallets. MetaMask, Trust Wallet, Phantom and Solflare are recognised by name and, if not
installed, shown with a link to their official download page. Connecting only shares
your public address. WalletConnect (mobile QR) is not included because it needs a relay service
and project ID, which does not fit a zero-cost, backend-free tool; use the CLI and sign in any
wallet instead. Wallet support is tested with simulated wallets only, not real extensions.

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
- ERC-20 and SPL tokens only: no NFT approvals and no Permit2.
- Browser wallet connections and Solana revoke have only been tested against simulated wallets,
  not real extensions; the CLI's base64 transaction is the fallback.
- Robinhood Chain has only two public RPCs configured (every other chain has three); override
  with `SWEEPSAFE_RPC_ROBINHOOD`. Public endpoints on every chain are rate-limited.
- The MyCrypto scam-address list URL could not be confirmed; if it is unreachable the scan
  continues with the other list and shows a warning.
- Addresses you type are not EIP-55 checksum-validated.
- Blocklists and verification services are third parties and can be wrong or offline.
- The web scanner calls RPCs and those services straight from your browser, so it needs them
  to allow cross-origin requests; the CLI has no such requirement.

## Support

Free and open source. Optional donations in USDC on Solana go straight to
`75DDnCQt4HPP5bF55oSBvSrwuCSLcC7U2w9tc3kMmyrA` (the same address as the Donate button on the
site; check they match before sending). Donations are voluntary, non-refundable and buy no
features or support.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## Enable the web viewer

Repository Settings → Pages → Source: **GitHub Actions**, then push to `main`.

MIT licensed.
