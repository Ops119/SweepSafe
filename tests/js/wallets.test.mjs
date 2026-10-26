import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const S = require("../../docs/sweepsafe.js");
const W = require("../../docs/wallets.js");

const PNG = "data:image/png;base64,iVBORw0KGgo=";
const SOL_OWNER = S.b58encode(new Uint8Array(32).fill(1));
const SOL_ACCT = S.b58encode(new Uint8Array(32).fill(4));
const SOL_HASH = S.b58encode(new Uint8Array(32).fill(9));

function fakeWindow(extra = {}) {
  const win = new EventTarget();
  win.Event = Event;
  win.CustomEvent = CustomEvent;
  return Object.assign(win, extra);
}
/** A page where wallets announce themselves when asked, like real EIP-6963 wallets. */
function evmWallet(win, info, provider) {
  win.addEventListener("eip6963:requestProvider", () =>
    win.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: { info, provider } })));
}
const eip1193 = (accounts) => ({ request: async ({ method }) => (method === "eth_requestAccounts" ? accounts : null) });

test("EIP-6963 discovery lists every announcing wallet once", () => {
  const win = fakeWindow();
  evmWallet(win, { uuid: "a", name: "Alpha", icon: PNG, rdns: "a.io" }, eip1193(["0x" + "AA".repeat(20)]));
  evmWallet(win, { uuid: "b", name: "Beta", icon: PNG, rdns: "b.io" }, eip1193([]));
  const w = W.init(win, S);
  win.dispatchEvent(new Event("eip6963:requestProvider")); // a second request must not duplicate
  assert.deepEqual(w.list("evm").map((x) => x.name), ["Alpha", "Beta"]);
  assert.equal(w.list("evm")[0].icon, PNG);
});

test("announcements that arrive late trigger onChange", () => {
  const win = fakeWindow();
  const w = W.init(win, S);
  let changes = 0;
  w.onChange(() => changes++);
  win.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: { info: { uuid: "z", name: "Late" }, provider: eip1193([]) } }));
  assert.equal(changes, 1);
  assert.deepEqual(w.list("evm").map((x) => x.name), ["Late"]);
});

test("window.ethereum is a fallback, but never duplicates an announced wallet", () => {
  const injected = eip1193([]);
  let win = fakeWindow({ ethereum: injected });
  assert.deepEqual(W.init(win, S).list("evm").map((x) => x.name), ["Browser wallet"]);
  win = fakeWindow({ ethereum: injected });
  evmWallet(win, { uuid: "a", name: "Alpha" }, injected);
  assert.deepEqual(W.init(win, S).list("evm").map((x) => x.name), ["Alpha"]);
  win = fakeWindow({ ethereum: injected });
  evmWallet(win, { uuid: "a", name: "Alpha" }, eip1193([]));
  assert.deepEqual(W.init(win, S).list("evm").map((x) => x.name), ["Alpha", "Browser wallet"]);
  assert.deepEqual(W.init(fakeWindow(), S).list("evm"), []);
});

test("hostile wallet metadata is neutralised", () => {
  const win = fakeWindow();
  evmWallet(win, { uuid: "x", name: '<img src=x onerror=alert(1)>\u0007' + "n".repeat(100), icon: "javascript:alert(1)" }, eip1193([]));
  evmWallet(win, { uuid: "y", name: "Svg", icon: 'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="onload="x' }, eip1193([]));
  evmWallet(win, { uuid: "bad", name: "NoRequest" }, {});
  evmWallet(win, null, eip1193([]));
  const list = W.init(win, S).list("evm");
  assert.equal(list.length, 2);
  assert.ok(!/[<>\u0007]/.test(list[0].name) && Array.from(list[0].name).length <= 32);
  assert.equal(list[0].icon, null);
  assert.equal(list[1].icon, null);
  assert.equal(W.cleanName("", "Fallback"), "Fallback");
});

test("connectEvm returns a lowercase address and rejects bad answers", async () => {
  const win = fakeWindow();
  evmWallet(win, { uuid: "a", name: "Alpha" }, eip1193(["0x" + "AB".repeat(20)]));
  evmWallet(win, { uuid: "b", name: "Empty" }, eip1193([]));
  evmWallet(win, { uuid: "c", name: "Junk" }, eip1193(["nope"]));
  const w = W.init(win, S);
  const [alpha, empty, junk] = w.list("evm");
  assert.equal(await w.connectEvm(alpha), "0x" + "ab".repeat(20));
  await assert.rejects(() => w.connectEvm(empty), /did not share/);
  await assert.rejects(() => w.connectEvm(junk), /did not share/);
});

function standardWallet(name, overrides = {}) {
  const calls = { connect: 0, sent: [] };
  const account = { address: SOL_OWNER };
  const wallet = {
    name, icon: PNG, chains: ["solana:mainnet"], accounts: [],
    features: {
      "standard:connect": { connect: async () => (calls.connect++, { accounts: [account] }) },
      "solana:signAndSendTransaction": {
        signAndSendTransaction: async (input) => (calls.sent.push(input), [{ signature: new Uint8Array(64).fill(3) }]),
      },
    },
    ...overrides,
  };
  return { wallet, calls, account };
}
/** Wallet Standard: wallets announce themselves by dispatching register-wallet with a callback. */
function registerStandard(win, wallet) {
  win.dispatchEvent(new CustomEvent("wallet-standard:register-wallet", { detail: (api) => api.register(wallet) }));
}

test("Wallet Standard wallets register before and after the app starts", () => {
  const win = fakeWindow();
  const early = standardWallet("Early");
  // A wallet that registered before the app loaded listens for app-ready.
  win.addEventListener("wallet-standard:app-ready", (e) => e.detail.register(early.wallet));
  const w = W.init(win, S);
  const late = standardWallet("Late");
  registerStandard(win, late.wallet);
  assert.deepEqual(w.list("solana").map((x) => x.name), ["Early", "Late"]);
});

test("Wallet Standard wallets without the needed features or mainnet are ignored", () => {
  const win = fakeWindow();
  const w = W.init(win, S);
  registerStandard(win, standardWallet("NoSend", { features: { "standard:connect": {} } }).wallet);
  registerStandard(win, standardWallet("Devnet", { chains: ["solana:devnet"] }).wallet);
  registerStandard(win, standardWallet("Evm", { chains: ["eip155:1"] }).wallet);
  registerStandard(win, standardWallet("NoChains", { chains: undefined }).wallet);
  registerStandard(win, standardWallet("Good").wallet);
  assert.deepEqual(w.list("solana").map((x) => x.name), ["Good"]);
});

test("Wallet Standard connect and send: unsigned bytes in, base58 signature out, one prompt", async () => {
  const win = fakeWindow();
  const w = W.init(win, S);
  const { wallet, calls, account } = standardWallet("Std");
  registerStandard(win, wallet);
  const entry = w.list("solana")[0];
  assert.equal(await entry.connect(), SOL_OWNER);
  assert.equal(await entry.connect(), SOL_OWNER);
  assert.equal(calls.connect, 1); // cached: no second wallet prompt
  const approval = { owner: SOL_OWNER, tokenAccount: SOL_ACCT, tokenProgram: S.SOLANA.tokenProgram };
  const reader = { call: async () => ({ value: { blockhash: SOL_HASH } }) };
  const sig = await S.sendSolanaRevoke(entry, reader, approval);
  assert.equal(sig, S.b58encode(new Uint8Array(64).fill(3)));
  const [input] = calls.sent;
  assert.equal(input.chain, "solana:mainnet");
  assert.equal(input.account, account);
  assert.equal(input.transaction[0], 1); // one signature slot...
  assert.ok(input.transaction.slice(1, 65).every((b) => b === 0)); // ...left empty for the wallet
});

test("Wallet Standard errors are explicit", async () => {
  const win = fakeWindow();
  const w = W.init(win, S);
  registerStandard(win, standardWallet("Silent", { features: {
    "standard:connect": { connect: async () => ({ accounts: [] }) },
    "solana:signAndSendTransaction": { signAndSendTransaction: async () => [] },
  } }).wallet);
  const entry = w.list("solana")[0];
  await assert.rejects(() => entry.connect(), /did not share an account/);
  const ok = standardWallet("NoSig", { features: {
    "standard:connect": { connect: async () => ({ accounts: [{ address: SOL_OWNER }] }) },
    "solana:signAndSendTransaction": { signAndSendTransaction: async () => [] },
  } });
  registerStandard(win, ok.wallet);
  await assert.rejects(() => w.list("solana").find((x) => x.name === "NoSig").signAndSend(new Uint8Array([1])), /did not return a signature/);
});

test("legacy injected Solana wallets work and never duplicate a standard wallet", async () => {
  const sent = [];
  const phantom = {
    async connect() { return { publicKey: { toString: () => SOL_OWNER } }; },
    async request(r) { sent.push(r); return { signature: "legacysig" }; },
  };
  let win = fakeWindow({ phantom: { solana: phantom }, solana: phantom });
  let list = W.init(win, S).list("solana");
  assert.deepEqual(list.map((x) => x.name), ["Phantom"]); // window.solana is the same object
  assert.equal(await list[0].connect(), SOL_OWNER);
  assert.equal(await list[0].signAndSend(new Uint8Array([1, 2, 3])), "legacysig");
  assert.equal(sent[0].method, "signAndSendTransaction");
  assert.equal(sent[0].params.message, S.b58encode(new Uint8Array([1, 2, 3])));

  win = fakeWindow({ phantom: { solana: phantom }, solflare: { connect: async () => ({}), publicKey: SOL_OWNER } });
  const std = standardWallet("Phantom");
  const w = W.init(win, S);
  registerStandard(win, std.wallet);
  assert.deepEqual(w.list("solana").map((x) => x.name), ["Phantom", "Solflare"]); // legacy Phantom hidden
  const solflare = w.list("solana")[1];
  assert.equal(await solflare.connect(), SOL_OWNER);
  await assert.rejects(() => solflare.signAndSend(new Uint8Array([1])), /Use the CLI/);
});

test("a window with no event support or wallets yields empty lists, not errors", () => {
  const w = W.init({}, S);
  assert.deepEqual(w.list("evm"), []);
  assert.deepEqual(w.list("solana"), []);
});

test("MetaMask, Trust Wallet, Phantom and Solflare are recognised however they announce", () => {
  const win = fakeWindow();
  evmWallet(win, { uuid: "1", name: "MetaMask", rdns: "io.metamask" }, eip1193([]));
  evmWallet(win, { uuid: "2", name: "Trust Wallet", rdns: "com.trustwallet.app" }, eip1193([]));
  evmWallet(win, { uuid: "3", name: "Some Other", rdns: "other.io" }, eip1193([]));
  const w = W.init(win, S);
  registerStandard(win, standardWallet("Phantom").wallet);
  registerStandard(win, standardWallet("Solflare").wallet);
  assert.deepEqual(w.list("evm").map((x) => x.known), ["metamask", "trust", null]);
  assert.deepEqual(w.list("solana").map((x) => x.known), ["phantom", "solflare"]);
  assert.deepEqual(w.missing("evm").map((x) => x.name), ["Phantom"]); // not installed for EVM
  assert.deepEqual(w.missing("solana"), []);
});

test("a spoofed name on the wrong kind of wallet does not count as installed", () => {
  const win = fakeWindow();
  evmWallet(win, { uuid: "1", name: "Solflare", rdns: "fake.io" }, eip1193([])); // Solflare is Solana-only
  const w = W.init(win, S);
  assert.equal(w.list("evm")[0].known, null);
  assert.ok(w.missing("evm").some((m) => m.key === "metamask"));
  assert.deepEqual(w.missing("solana").map((m) => m.name), ["Phantom", "Solflare"]);
});

test("missing wallets come with fixed official install links", () => {
  const w = W.init(fakeWindow(), S);
  assert.deepEqual(w.missing("evm").map((m) => m.name), ["MetaMask", "Trust Wallet", "Phantom"]);
  assert.deepEqual(w.missing("solana").map((m) => m.name), ["Phantom", "Solflare"]);
  const hosts = new Set(["metamask.io", "trustwallet.com", "phantom.com", "www.solflare.com"]);
  for (const k of W.KNOWN) {
    const u = new URL(k.install);
    assert.equal(u.protocol, "https:");
    assert.ok(hosts.has(u.hostname), k.install);
  }
});

test("Phantom's own EVM provider is found even when it did not announce itself", () => {
  const phantomEth = { isPhantom: true, request: async () => [] };
  const win = fakeWindow({ phantom: { ethereum: phantomEth }, ethereum: phantomEth });
  const list = W.init(win, S).list("evm");
  assert.deepEqual(list.map((x) => x.name), ["Phantom"]); // same object as window.ethereum: no duplicate
  assert.equal(list[0].known, "phantom");
  // A page that merely claims isPhantom without request() is ignored.
  assert.deepEqual(W.init(fakeWindow({ phantom: { ethereum: { isPhantom: true } } }), S).list("evm"), []);
  // Something that is not Phantom at window.phantom.ethereum is not labelled Phantom.
  assert.deepEqual(W.init(fakeWindow({ phantom: { ethereum: { request: async () => [] } } }), S).list("evm"), []);
});
