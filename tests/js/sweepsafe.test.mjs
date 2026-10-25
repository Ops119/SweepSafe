import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const S = require("../../docs/sweepsafe.js");
const rules = S.parseRules(readFileSync(new URL("../../docs/rules.json", import.meta.url), "utf8"));
const parityCases = JSON.parse(readFileSync(new URL("../fixtures/parity_cases.json", import.meta.url), "utf8"));

const OWNER = "0x" + "11".repeat(20);
const TOKEN_A = "0x" + "aa".repeat(20);
const TOKEN_B = "0x" + "bb".repeat(20);
const SPENDER_1 = "0x" + "c1".repeat(20);
const SPENDER_2 = "0x" + "c2".repeat(20);
const SPENDER_3 = "0x" + "c3".repeat(20);
const MAX = (1n << 256n) - 1n;
const CODE = "0x6080604052";
const NOW = 1_800_000_000;
const DAY = 86_400;
const THRESHOLD = 1n << 255n;

// ------------------------------------------------------------------ helpers
function abiString(text) {
  const raw = Buffer.from(text);
  const padded = Buffer.concat([raw, Buffer.alloc((32 - (raw.length % 32)) % 32)]);
  const word = (n) => n.toString(16).padStart(64, "0");
  return "0x" + word(32) + word(raw.length) + padded.toString("hex");
}
function makeLog(token, owner, spender, value, block, logIndex = 0) {
  return {
    address: token,
    topics: [S.APPROVAL_TOPIC, S.addressToTopic(owner), S.addressToTopic(spender)],
    data: "0x" + S.encodeUint256(value),
    blockNumber: "0x" + block.toString(16),
    logIndex: "0x" + logIndex.toString(16),
    transactionHash: "0x" + block.toString(16).padStart(32, "0") + logIndex.toString(16).padStart(32, "0"),
    removed: false,
  };
}
class FakeNode {
  constructor({ head = 1000, logs = [], allowances = {}, tokens = {}, codes = {}, timestamps = {}, maxRange = null } = {}) {
    Object.assign(this, { head, logs, allowances, tokens, codes, timestamps, maxRange });
    this.logRequests = [];
    this.calls = [];
  }
  async blockNumber() { return this.head; }
  async getLogs(from, to, topics) {
    this.logRequests.push([from, to]);
    if (this.maxRange !== null && to - from + 1 > this.maxRange) {
      throw new S.RpcError(-32602, "query exceeds max block range of 10000");
    }
    return this.logs.filter((l) => {
      const b = Number(BigInt(l.blockNumber));
      return b >= from && b <= to && l.topics[0] === topics[0] && l.topics[1] === topics[1];
    });
  }
  async ethCall(to, data) {
    this.calls.push([to, data.slice(0, 10)]);
    const sel = data.slice(0, 10);
    if (sel === S.SELECTORS.allowance) {
      const spender = "0x" + data.slice(10 + 64 + 24);
      const key = to + ":" + spender;
      if (key in this.allowances) return "0x" + S.encodeUint256(this.allowances[key]);
      throw new S.RpcError(3, "execution reverted");
    }
    if (sel === S.SELECTORS.symbol && to in this.tokens) return abiString(this.tokens[to][0]);
    if (sel === S.SELECTORS.decimals && to in this.tokens) return "0x" + S.encodeUint256(BigInt(this.tokens[to][1]));
    throw new S.RpcError(3, "execution reverted");
  }
  async getCode(address) { return this.codes[address] || "0x"; }
  async getBlockTimestamp(n) {
    if (!(n in this.timestamps)) throw new S.RpcError(-32000, "header not found");
    return this.timestamps[n];
  }
}
function walletNode() {
  return new FakeNode({
    head: 2000,
    logs: [
      makeLog(TOKEN_A, OWNER, SPENDER_1, MAX, 100),
      makeLog(TOKEN_A, OWNER, SPENDER_2, 500_000_000n, 200),
      makeLog(TOKEN_B, OWNER, SPENDER_3, 7n, 300),
    ],
    allowances: {
      [TOKEN_A + ":" + SPENDER_1]: MAX,
      [TOKEN_A + ":" + SPENDER_2]: 500_000_000n,
      [TOKEN_B + ":" + SPENDER_3]: 7n,
    },
    tokens: { [TOKEN_A]: ["USDC", 6], [TOKEN_B]: ["WETH", 18] },
    codes: { [SPENDER_1]: CODE, [SPENDER_3]: CODE },
    timestamps: { 100: NOW - 400 * DAY, 200: NOW - 5 * DAY, 300: NOW - DAY },
  });
}
const chain = { name: "testnet", id: 1, rpcs: ["https://x.example"], explorer: "https://scan.example", blockscout: null, reorgDepth: 10, startBlock: 0 };
const res = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

// ------------------------------------------------------------------ ABI + formatting
test("abi encoding", () => {
  const data = S.encodeApprove(SPENDER_1, 0n);
  assert.equal(data, "0x095ea7b3" + SPENDER_1.slice(2).padStart(64, "0") + "0".repeat(64));
  assert.equal(S.encodeAllowanceCall(OWNER, SPENDER_1).length, 2 + 8 + 128);
  assert.equal(S.topicToAddress(S.addressToTopic(OWNER)), OWNER);
  assert.throws(() => S.topicToAddress("0x1234"), S.AbiError);
  assert.throws(() => S.normalizeAddress("nope"), S.AbiError);
  assert.throws(() => S.encodeUint256(-1n), S.AbiError);
  assert.throws(() => S.encodeUint256(MAX + 1n), S.AbiError);
  assert.equal(S.encodeUint256(MAX), "f".repeat(64));
});

test("decodeUint256 and hexToInt are strict", () => {
  assert.equal(S.decodeUint256("0x" + "00".repeat(31) + "05"), 5n);
  for (const bad of ["0x", "0x00", "0x" + "00".repeat(33), "zz", null]) assert.throws(() => S.decodeUint256(bad), S.AbiError);
  assert.equal(S.hexToInt("0x1b4"), 436);
  assert.throws(() => S.hexToInt("0x"), S.AbiError);
  assert.throws(() => S.hexToInt(5), S.AbiError);
});

test("decodeString handles abi strings, bytes32, hostile and malformed input", () => {
  assert.equal(S.decodeString(abiString("USDC")), "USDC");
  assert.equal(S.decodeString("0x" + Buffer.from("MKR").toString("hex").padEnd(64, "0")), "MKR");
  const hostile = S.decodeString(abiString("<b>\u0007evil\n" + "x".repeat(100)));
  assert.ok(!hostile.includes("\u0007") && !hostile.includes("\n"));
  assert.ok(Array.from(hostile).length <= 32);
  assert.equal(S.decodeString("0x"), null);
  assert.equal(S.decodeString("0x" + "00".repeat(10)), null);
  assert.equal(S.decodeString("zz"), null);
  assert.equal(S.decodeString("0x" + (10000).toString(16).padStart(64, "0") + "00".repeat(32)), null);
  assert.equal(S.decodeString("0x" + (32).toString(16).padStart(64, "0") + (10 ** 9).toString(16).padStart(64, "0")), null);
  assert.equal(S.decodeString(abiString("")), null);
});

test("formatAmount matches the Python table", () => {
  const cases = [
    [0n, 18, "0"], [1n, 18, "<0.0001"], [1n, 0, "1"], [10n ** 18n, 18, "1"], [1_500_000n, 6, "1.5"],
    [1234567n, 3, "1,234.567"], [123n, 6, "0.0001"], [99n, 6, "<0.0001"], [100_000_000_000n, 6, "100,000"],
    [5n, null, "5 raw units"], [5n, 78, "5 raw units"], [THRESHOLD, 18, "unlimited"],
    [THRESHOLD - 1n, null, `${THRESHOLD - 1n} raw units`],
    [5n * 10n ** 76n, 77, "0.5"], [10n ** 77n, 77, "unlimited"],
  ];
  for (const [value, decimals, expected] of cases) assert.equal(S.formatAmount(value, decimals, THRESHOLD), expected, `${value}/${decimals}`);
  assert.equal(S.shortAddress(SPENDER_1), "0xc1c1…c1c1");
});

// ------------------------------------------------------------------ risk + explain parity
test("risk and explanations match the shared fixtures exactly", () => {
  assert.ok(parityCases.length >= 8);
  for (const c of parityCases) {
    const risk = S.evaluateRisk(rules, {
      allowance: BigInt(c.input.allowance),
      spender_is_contract: c.input.spender_is_contract,
      verification: c.input.verification,
      blocklisted: c.input.blocklisted,
      age_days: c.input.age_days,
    });
    assert.equal(risk.score, c.expected.score, c.name);
    assert.equal(risk.level, c.expected.level, c.name);
    assert.deepEqual(risk.findings.map((f) => f.rule_id), c.expected.rule_ids, c.name);
    const approval = { token: c.token, spender: c.spender, allowance: BigInt(c.input.allowance), tokenSymbol: c.token_symbol, tokenDecimals: c.token_decimals };
    assert.equal(S.explainApproval(rules, approval, risk), c.expected.explanation, c.name);
  }
});

test("level boundaries and age helper", () => {
  const table = [[0, "low"], [24, "low"], [25, "medium"], [49, "medium"], [50, "high"], [74, "high"], [75, "critical"], [100, "critical"]];
  for (const [score, level] of table) assert.equal(S.levelFor(rules, score), level);
  assert.equal(S.ageInDays(null, 1000), null);
  assert.equal(S.ageInDays(0, DAY * 3 + 5), 3);
  assert.equal(S.ageInDays(2000, 1000), 0);
});

test("fillTemplate is single pass", () => {
  assert.equal(S.fillTemplate("{a} {b} {missing}", { a: "{b}", b: "x" }), "{b} x {missing}");
  assert.equal(S.fillTemplate("{toString}", {}), "{toString}"); // prototype keys never leak
});

// ------------------------------------------------------------------ RPC client
function scriptedFetch(script) {
  const requests = [];
  const impl = async (url, init) => {
    const method = init && init.body ? JSON.parse(init.body).method : "GET";
    requests.push([url, method]);
    const queue = script[url];
    const item = queue.length > 1 ? queue.shift() : queue[0];
    if (item instanceof Error) throw item;
    return typeof item === "function" ? item() : item;
  };
  impl.requests = requests;
  return impl;
}
const ok = (result) => res({ jsonrpc: "2.0", id: 1, result });
const err = (code, message) => res({ jsonrpc: "2.0", id: 1, error: { code, message } });
const URLS = ["https://rpc-a.example", "https://rpc-b.example", "https://rpc-c.example"];
function makeRpc(script, extra = {}) {
  const sleeps = [];
  const fetchImpl = scriptedFetch(script);
  const rpc = S.createRpc({ urls: extra.urls || URLS, fetch: fetchImpl, minIntervalMs: 0, sleep: async (ms) => void sleeps.push(ms), ...extra });
  return { rpc, sleeps, fetchImpl };
}

test("rpc success, rotation on rate limits, and exponential backoff", async () => {
  const { rpc, sleeps, fetchImpl } = makeRpc(
    {
      [URLS[0]]: [res({}, 429)],
      [URLS[1]]: [err(-32005, "rate limit exceeded"), ok("0x2")],
      [URLS[2]]: [ok("0x2")],
    },
    { backoffMs: 1000 }
  );
  assert.equal(await rpc.blockNumber(), 2);
  assert.deepEqual(fetchImpl.requests.map((r) => r[0]), [URLS[0], URLS[1], URLS[2]]);
  assert.deepEqual(sleeps, [1000, 2000]);
});

test("rpc gives up after retries and reports unavailable", async () => {
  const { rpc, fetchImpl } = makeRpc(Object.fromEntries(URLS.map((u) => [u, [res({}, 500)]])), { retries: 2 });
  await assert.rejects(() => rpc.blockNumber(), S.RpcUnavailableError);
  assert.equal(fetchImpl.requests.length, 3);
});

test("reverts and range errors are not retried", async () => {
  let { rpc, fetchImpl } = makeRpc({ [URLS[0]]: [err(3, "execution reverted")] });
  await assert.rejects(() => rpc.call("eth_call", [{}, "latest"]), (e) => e instanceof S.RpcError && e.isRevert);
  assert.equal(fetchImpl.requests.length, 1);
  ({ rpc, fetchImpl } = makeRpc({ [URLS[0]]: [err(-32602, "query exceeds max block range 10000")] }));
  await assert.rejects(() => rpc.getLogs(0, 100000, []), (e) => e.isRangeError && !e.retriable);
  assert.equal(fetchImpl.requests.length, 1);
});

test("a provider on the wrong chain is skipped and never used again", async () => {
  const { rpc, fetchImpl } = makeRpc(
    { [URLS[0]]: [ok("0x89")], [URLS[1]]: [ok("0x1"), ok("0x20")] },
    { urls: URLS.slice(0, 2), expectedChainId: 1 }
  );
  assert.equal(await rpc.blockNumber(), 32);
  assert.equal(await rpc.blockNumber(), 32);
  assert.deepEqual(fetchImpl.requests.map((r) => r[1]), ["eth_chainId", "eth_chainId", "eth_blockNumber", "eth_blockNumber"]);
  assert.ok(fetchImpl.requests.slice(2).every(([u]) => u === URLS[1]));
});

test("all providers on the wrong chain raises ChainMismatchError", async () => {
  const { rpc } = makeRpc({ [URLS[0]]: [ok("0x89")], [URLS[1]]: [ok("0x89")] }, { urls: URLS.slice(0, 2), expectedChainId: 1 });
  await assert.rejects(() => rpc.blockNumber(), S.ChainMismatchError);
});

test("malformed responses are retried; missing result is an error", async () => {
  let { rpc } = makeRpc({ [URLS[0]]: [res("not an object"), ok("0x5")], [URLS[1]]: [ok("0x5")] });
  assert.equal(await rpc.blockNumber(), 5);
  ({ rpc } = makeRpc(Object.fromEntries(URLS.map((u) => [u, [res({ jsonrpc: "2.0", id: 1 })]])), { retries: 1 }));
  await assert.rejects(() => rpc.blockNumber(), S.RpcUnavailableError);
});

test("network errors and bad json are retriable", async () => {
  const { rpc } = makeRpc({ [URLS[0]]: [new Error("offline"), { ok: true, status: 200, json: async () => { throw new Error("html"); } }], [URLS[1]]: [ok("0x7")] });
  assert.equal(await rpc.blockNumber(), 7);
});

test("throttle spaces requests", async () => {
  const sleeps = [];
  let t = 0;
  const rpc = S.createRpc({ urls: URLS.slice(0, 1), fetch: scriptedFetch({ [URLS[0]]: [ok("0x1")] }), minIntervalMs: 500, now: () => t, sleep: async (ms) => { sleeps.push(ms); t += ms; } });
  await rpc.blockNumber();
  await rpc.blockNumber();
  assert.equal(sleeps[0], 500);
});

test("rpc refuses insecure or invalid urls", () => {
  assert.throws(() => S.createRpc({ urls: [] }), /at least one/);
  assert.throws(() => S.createRpc({ urls: ["http://insecure.example"] }), S.TransportError);
  assert.throws(() => S.createRpc({ urls: ["not a url"] }), S.TransportError);
  S.createRpc({ urls: ["http://localhost:8545"], fetch: async () => {} });
});

test("typed rpc helpers validate shapes", async () => {
  await assert.rejects(() => makeRpc({ [URLS[0]]: [ok("nope")] }).rpc.getLogs(0, 1, []), S.TransportError);
  await assert.rejects(() => makeRpc({ [URLS[0]]: [ok(5)] }).rpc.ethCall(TOKEN_A, "0x"), S.TransportError);
  await assert.rejects(() => makeRpc({ [URLS[0]]: [ok(5)] }).rpc.getCode(TOKEN_A), S.TransportError);
  await assert.rejects(() => makeRpc({ [URLS[0]]: [ok(null)] }).rpc.getBlockTimestamp(1), S.TransportError);
  const { rpc } = makeRpc({ [URLS[0]]: [ok([{ x: 1 }]), ok("0xdead"), ok("0x6080"), ok({ timestamp: "0x64" })] });
  assert.deepEqual(await rpc.getLogs(1, 2, ["0x1"]), [{ x: 1 }]);
  assert.equal(await rpc.ethCall(TOKEN_A, "0x"), "0xdead");
  assert.equal(await rpc.getCode(TOKEN_A), "0x6080");
  assert.equal(await rpc.getBlockTimestamp(5), 100);
});

test("rpc error classification mirrors Python", () => {
  assert.ok(new S.RpcError(-32000, "header not found").retriable);
  assert.ok(new S.RpcError(-32000, "daily request limit reached, rate limit").retriable);
  assert.ok(!new S.RpcError(-32602, "invalid params").retriable);
  assert.ok(new S.RpcError(-32000, "Log response size exceeded").isRangeError);
  assert.ok(new S.RpcError(3, "").isRevert);
});

// ------------------------------------------------------------------ log scanning
test("parseApprovalLog accepts ERC-20 and ignores everything else", () => {
  const good = makeLog(TOKEN_A, OWNER, SPENDER_1, 7n, 123, 4);
  const parsed = S.parseApprovalLog({ ...good, transactionHash: "0xAB" }, OWNER);
  assert.deepEqual([parsed.token, parsed.spender, parsed.value, parsed.blockNumber, parsed.logIndex, parsed.txHash], [TOKEN_A, SPENDER_1, 7n, 123, 4, "0xab"]);
  const nft = { ...good, topics: [...good.topics, "0x" + "00".repeat(32)], data: "0x" };
  assert.equal(S.parseApprovalLog(nft, OWNER), null);
  assert.equal(S.parseApprovalLog({ ...good, removed: true }, OWNER), null);
  assert.equal(S.parseApprovalLog(makeLog(TOKEN_A, SPENDER_2, SPENDER_1, 1n, 1), OWNER), null);
  assert.equal(S.parseApprovalLog({ ...good, data: "0x01" }, OWNER), null);
  assert.equal(S.parseApprovalLog({ ...good, data: null }, OWNER), null);
  assert.equal(S.parseApprovalLog({ ...good, blockNumber: "zz" }, OWNER), null);
  assert.equal(S.parseApprovalLog({ ...good, topics: "nope" }, OWNER), null);
  assert.equal(S.parseApprovalLog(null, OWNER), null);
});

test("chunk size adapts to node limits without gaps", async () => {
  const node = new FakeNode({ maxRange: 1000, logs: [makeLog(TOKEN_A, OWNER, SPENDER_1, 1n, 5432)] });
  const chunks = [];
  await S.fetchApprovalLogs(node, OWNER, 0, 10000, { initialChunk: 8000, minChunk: 100, onChunk: (a, b, logs) => chunks.push([a, b, logs]) });
  assert.equal(chunks[0][0], 0);
  assert.equal(chunks.at(-1)[1], 10000);
  for (let i = 1; i < chunks.length; i++) assert.equal(chunks[i][0], chunks[i - 1][1] + 1);
  assert.deepEqual(chunks.flatMap((c) => c[2]).map((l) => l.blockNumber), [5432]);
  assert.ok(chunks.every(([a, b]) => b - a + 1 <= 1000));
});

test("chunk grows over empty ranges and shrinks when dense", async () => {
  const empty = new FakeNode();
  await S.fetchApprovalLogs(empty, OWNER, 0, 1_000_000, { initialChunk: 100, maxChunk: 100000 });
  assert.ok(empty.logRequests.length < 20);
  const dense = new FakeNode({ logs: [0, 1, 2].map((i) => makeLog(TOKEN_A, OWNER, SPENDER_1, BigInt(i + 1), 10 + i, i)) });
  await S.fetchApprovalLogs(dense, OWNER, 0, 1000, { initialChunk: 400, minChunk: 50, dense: 2 });
  const sizes = dense.logRequests.map(([a, b]) => b - a + 1);
  assert.ok(sizes[1] < sizes[0]);
});

test("ScanError when the node rejects even the minimum range; other errors propagate", async () => {
  await assert.rejects(() => S.fetchApprovalLogs(new FakeNode({ maxRange: 10 }), OWNER, 0, 1000, { initialChunk: 100, minChunk: 50 }), S.ScanError);
  const broken = { getLogs: async () => { throw new S.RpcError(-32601, "method not found"); } };
  await assert.rejects(() => S.fetchApprovalLogs(broken, OWNER, 0, 10), S.RpcError);
});

test("syncLogs resumes from the tail, drops reorged logs, and honours fromBlock/reset", async () => {
  const cache = S.memoryCache();
  const node = new FakeNode({ head: 1000, logs: [makeLog(TOKEN_A, OWNER, SPENDER_1, 5n, 100), makeLog(TOKEN_A, OWNER, SPENDER_2, 5n, 995)] });
  let out = await S.syncLogs({ reader: node, chain, owner: OWNER, cache });
  assert.equal(out.logs.length, 2);
  assert.equal(out.scannedTo, 1000);

  node.head = 1500;
  node.logs.splice(1, 1); // block 995 was reorged away
  node.logs.push(makeLog(TOKEN_B, OWNER, SPENDER_1, 9n, 1200));
  node.logRequests.length = 0;
  out = await S.syncLogs({ reader: node, chain, owner: OWNER, cache });
  assert.equal(node.logRequests[0][0], 1000 - chain.reorgDepth + 1); // tail only, not genesis
  assert.deepEqual(out.logs.map((l) => l.blockNumber).sort((a, b) => a - b), [100, 1200]);

  node.logRequests.length = 0;
  await S.syncLogs({ reader: node, chain, owner: OWNER, cache, reset: true });
  assert.equal(node.logRequests[0][0], 0);

  const fresh = S.memoryCache();
  out = await S.syncLogs({ reader: node, chain, owner: OWNER, cache: fresh, fromBlock: 500 });
  assert.deepEqual(out.logs.map((l) => l.blockNumber), [1200]);
  assert.ok(out.warnings.some((w) => w.includes("History before block 500")));
  node.logRequests.length = 0;
  out = await S.syncLogs({ reader: node, chain, owner: OWNER, cache: fresh, fromBlock: 0 });
  assert.equal(node.logRequests[0][0], 0); // older history requested: restart honestly
  assert.deepEqual(out.warnings, []);
});

test("syncLogs is a no-op when the provider lags behind the cursor", async () => {
  const cache = S.memoryCache();
  const node = new FakeNode({ head: 1000, logs: [makeLog(TOKEN_A, OWNER, SPENDER_1, 5n, 100)] });
  await S.syncLogs({ reader: node, chain, owner: OWNER, cache });
  node.head = 500;
  const out = await S.syncLogs({ reader: node, chain, owner: OWNER, cache });
  assert.equal(out.scannedTo, 1000);
  assert.equal(out.logs.length, 1);
});

test("storageCache survives blocked or full storage", () => {
  const throwing = { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("full"); } };
  const cache = S.storageCache(throwing);
  cache.set("k", { a: 1 });
  assert.deepEqual(cache.get("k"), { a: 1 });
  const map = new Map();
  const real = S.storageCache({ getItem: (k) => (map.has(k) ? map.get(k) : null), setItem: (k, v) => void map.set(k, v) });
  real.set("x", { b: 2 });
  assert.equal(map.get("x"), '{"b":2}');
  assert.deepEqual(real.get("x"), { b: 2 });
});

// ------------------------------------------------------------------ approvals + orchestration
test("activeApprovals uses the live allowance and skips revoked, spent and unreadable ones", async () => {
  const nft = makeLog(TOKEN_B, OWNER, SPENDER_2, 1n, 55);
  nft.topics.push("0x" + "00".repeat(32));
  nft.data = "0x";
  const node = new FakeNode({
    head: 1000,
    logs: [
      makeLog(TOKEN_A, OWNER, SPENDER_1, 100n, 10),
      makeLog(TOKEN_A, OWNER, SPENDER_1, 0n, 20),
      makeLog(TOKEN_A, OWNER, SPENDER_2, MAX, 30),
      makeLog(TOKEN_B, OWNER, SPENDER_1, 50n, 40),
      makeLog(TOKEN_B, OWNER, SPENDER_2, 5n, 50),
      nft,
    ],
    allowances: { [TOKEN_A + ":" + SPENDER_1]: 0n, [TOKEN_A + ":" + SPENDER_2]: MAX, [TOKEN_B + ":" + SPENDER_1]: 0n },
    tokens: { [TOKEN_A]: ["USDC", 6] },
    timestamps: { 30: 1_700_000_000 },
  });
  const { logs } = await S.syncLogs({ reader: node, chain, owner: OWNER, cache: S.memoryCache() });
  const { approvals, warnings } = await S.activeApprovals({ reader: node, chain, owner: OWNER, logs });
  assert.deepEqual(approvals.map((a) => [a.token, a.spender]), [[TOKEN_A, SPENDER_2]]);
  assert.equal(approvals[0].allowance, MAX);
  assert.deepEqual([approvals[0].tokenSymbol, approvals[0].tokenDecimals, approvals[0].timestamp], ["USDC", 6, 1_700_000_000]);
  assert.ok(warnings.some((w) => w.includes("Could not read allowance") && w.includes(TOKEN_B)));
});

test("latest event wins within one block; missing timestamp degrades gracefully", async () => {
  const node = new FakeNode({
    head: 100,
    logs: [makeLog(TOKEN_A, OWNER, SPENDER_1, 0n, 10, 5), makeLog(TOKEN_A, OWNER, SPENDER_1, 9n, 10, 2)],
    allowances: { [TOKEN_A + ":" + SPENDER_1]: 9n },
  });
  const { logs } = await S.syncLogs({ reader: node, chain, owner: OWNER });
  assert.deepEqual((await S.activeApprovals({ reader: node, chain, owner: OWNER, logs })).approvals, []);

  const node2 = new FakeNode({ head: 100, logs: [makeLog(TOKEN_A, OWNER, SPENDER_1, 9n, 10)], allowances: { [TOKEN_A + ":" + SPENDER_1]: 9n } });
  const synced = await S.syncLogs({ reader: node2, chain, owner: OWNER });
  const out = await S.activeApprovals({ reader: node2, chain, owner: OWNER, logs: synced.logs });
  assert.equal(out.approvals[0].timestamp, null);
  assert.ok(out.warnings.some((w) => w.includes("Could not read the date of block 10")));
  assert.deepEqual([out.approvals[0].tokenSymbol, out.approvals[0].tokenDecimals], [null, null]);
});

test("isContractCode and classifySpender", async () => {
  assert.equal(S.isContractCode("0x"), false);
  assert.equal(S.isContractCode("0x0"), false);
  assert.equal(S.isContractCode(CODE), true);
  assert.equal(S.isContractCode("0xef0100" + "ab".repeat(20)), false); // EIP-7702 delegated wallet
  assert.equal(S.isContractCode("0xef0100" + "ab".repeat(21)), true);
  assert.equal(await S.classifySpender(new FakeNode({ codes: { [SPENDER_1]: CODE } }), SPENDER_1), true);
  assert.equal(await S.classifySpender(new FakeNode(), SPENDER_1), false);
  const down = { getCode: async () => { throw new S.TransportError("net"); } };
  assert.equal(await S.classifySpender(down, SPENDER_1), null);
});

const BLOCKLIST_URL = "https://lists.example/scams.json";
function apiFetch({ blocklists = {}, verified = [] } = {}) {
  const calls = [];
  const impl = async (url) => {
    calls.push(url);
    if (url in blocklists) {
      const v = blocklists[url];
      if (v instanceof Error) throw v;
      return res(v);
    }
    const m = /\/(contract\/\d+|smart-contracts)\/(0x[0-9a-f]{40})$/.exec(url) || /smart-contracts\/(0x[0-9a-f]{40})$/.exec(url);
    if (m && verified.includes(url.slice(-42))) return res({ is_verified: true, match: "exact_match" });
    return res({ message: "not found" }, 404);
  };
  impl.calls = calls;
  return impl;
}

test("scanWallet end to end: scoring, ordering, blocklist, verification", async () => {
  const fetchImpl = apiFetch({ blocklists: { [BLOCKLIST_URL]: [SPENDER_3] } });
  const blocklist = await S.loadBlocklist({ fetchImpl, urls: [BLOCKLIST_URL], cache: S.memoryCache() });
  const result = await S.scanWallet({ reader: walletNode(), chain, rules, owner: OWNER.toUpperCase().replace("0X", "0x"), fetchImpl, blocklist, cache: S.memoryCache(), nowSec: NOW });
  assert.equal(result.owner, OWNER);
  assert.equal(result.scannedToBlock, 2000);
  assert.deepEqual(result.approvals.map((a) => [a.approval.spender, a.risk.score, a.risk.level]), [
    [SPENDER_3, 100, "critical"], [SPENDER_1, 70, "high"], [SPENDER_2, 30, "medium"],
  ]);
  assert.ok(result.approvals[0].explanation.includes("blocklist"));
  assert.ok(result.approvals[1].explanation.startsWith("USDC: unlimited allowance for"));
  assert.deepEqual(result.warnings, []);
  // EOA spenders never trigger a verification lookup.
  assert.ok(!fetchImpl.calls.some((u) => u.includes(SPENDER_2)));
});

test("scanWallet marks verified contracts as such and surfaces blocklist warnings", async () => {
  const fetchImpl = apiFetch({ verified: [SPENDER_1, SPENDER_3] });
  const blocklist = { addresses: new Set(), warnings: ["Blocklist source unavailable (no cached copy): x"] };
  const result = await S.scanWallet({ reader: walletNode(), chain, rules, owner: OWNER, fetchImpl, blocklist, nowSec: NOW });
  const by = Object.fromEntries(result.approvals.map((a) => [a.approval.spender, a]));
  assert.deepEqual(by[SPENDER_1].risk.findings.map((f) => f.rule_id), ["unlimited_allowance", "stale_approval"]);
  assert.deepEqual(by[SPENDER_3].risk.findings, []);
  assert.ok(result.warnings.some((w) => w.includes("Blocklist source unavailable")));
});

// ------------------------------------------------------------------ blocklist + verification
test("parseAddressList handles known shapes and never leaks allowlists", () => {
  assert.deepEqual([...S.parseAddressList([SPENDER_1.toUpperCase().replace("0X", "0x"), "nope", 5, null])], [SPENDER_1]);
  assert.deepEqual([...S.parseAddressList([{ address: SPENDER_1, comment: "scam" }, { address: SPENDER_2 }])].sort(), [SPENDER_1, SPENDER_2]);
  assert.deepEqual([...S.parseAddressList({ blacklist: [SPENDER_1], whitelist: [SPENDER_2], safe_list: [SPENDER_3], Allowed: [SPENDER_3] })], [SPENDER_1]);
  assert.equal(S.parseAddressList("0x1234").size, 0);
  assert.equal(S.parseAddressList(null).size, 0);
});

test("loadBlocklist caches within TTL, falls back to stale, reports failures", async () => {
  const cache = S.memoryCache();
  let t = 1_000_000;
  const fetchImpl = apiFetch({ blocklists: { [BLOCKLIST_URL]: [SPENDER_1] } });
  let out = await S.loadBlocklist({ fetchImpl, urls: [BLOCKLIST_URL], cache, now: () => t });
  assert.ok(out.addresses.has(SPENDER_1) && out.warnings.length === 0);
  fetchImpl.calls.length = 0;
  await S.loadBlocklist({ fetchImpl, urls: [BLOCKLIST_URL], cache, now: () => t + 1000 });
  assert.equal(fetchImpl.calls.length, 0);

  const down = apiFetch({ blocklists: { [BLOCKLIST_URL]: new Error("offline") } });
  out = await S.loadBlocklist({ fetchImpl: down, urls: [BLOCKLIST_URL], cache, now: () => t + 2 * 86_400_000 });
  assert.ok(out.addresses.has(SPENDER_1));
  assert.ok(out.warnings[0].includes("cached copy"));
  out = await S.loadBlocklist({ fetchImpl: down, urls: [BLOCKLIST_URL], cache: S.memoryCache(), now: () => t });
  assert.equal(out.addresses.size, 0);
  assert.ok(out.warnings[0].includes("unavailable"));
});

test("checkVerification: verified wins, unverified only when definitive, unknown never cached", async () => {
  const eth = S.CHAINS.ethereum;
  const verified = apiFetch({ verified: [SPENDER_1] });
  assert.equal(await S.checkVerification({ fetchImpl: verified, chain: eth, address: SPENDER_1 }), "verified");
  assert.equal(await S.checkVerification({ fetchImpl: apiFetch(), chain: eth, address: SPENDER_1 }), "unverified");
  const outage = async () => res({}, 503);
  assert.equal(await S.checkVerification({ fetchImpl: outage, chain: eth, address: SPENDER_1 }), "unknown");
  const cache = S.memoryCache();
  let calls = 0;
  const counting = async (url) => (calls++, res({ match: "exact_match" }));
  await S.checkVerification({ fetchImpl: counting, chain: eth, address: SPENDER_1, cache, now: 1000 });
  await S.checkVerification({ fetchImpl: counting, chain: eth, address: SPENDER_1, cache, now: 2000 });
  assert.equal(calls, 1);
  const unknownCache = S.memoryCache();
  calls = 0;
  const flaky = async () => (calls++, res({}, 500));
  await S.checkVerification({ fetchImpl: flaky, chain: eth, address: SPENDER_1, cache: unknownCache, now: 1 });
  await S.checkVerification({ fetchImpl: flaky, chain: eth, address: SPENDER_1, cache: unknownCache, now: 2 });
  assert.ok(calls >= 4); // both providers asked twice: unknown is never cached
  const noScout = { ...eth, blockscout: null };
  assert.equal(await S.checkVerification({ fetchImpl: apiFetch(), chain: noScout, address: SPENDER_1 }), "unverified");
});

test("getJson refuses insecure URLs and maps HTTP errors", async () => {
  await assert.rejects(() => S.getJson(async () => res({}), "http://evil.example"), S.TransportError);
  await assert.rejects(() => S.getJson(async () => res({}, 404), "https://x.example"), (e) => e.status === 404 && !e.retriable);
  await assert.rejects(() => S.getJson(async () => res({}, 429), "https://x.example"), (e) => e.retriable);
  await assert.rejects(() => S.getJson(async () => ({ ok: true, status: 200, json: async () => { throw new Error("x"); } }), "https://x.example"), /invalid JSON/);
  assert.deepEqual(await S.getJson(async () => res([1, 2]), "https://x.example"), [1, 2]);
});

// ------------------------------------------------------------------ share links + wallet
test("share-link hash round trip rejects anything malformed", () => {
  const hash = S.buildHash("base", OWNER.toUpperCase().replace("0X", "0x"));
  assert.equal(hash, "#base:" + OWNER);
  assert.deepEqual(S.parseHash(hash), { chain: "base", address: OWNER });
  assert.deepEqual(S.parseHash("eth:" + OWNER), { chain: "ethereum", address: OWNER });
  for (const bad of ["", "#", "#base:0x1234", "#solana:" + OWNER, "#base:" + OWNER + "x", "#<script>:" + OWNER, null, undefined, "#base:javascript:alert(1)"]) {
    assert.equal(S.parseHash(bad), null, String(bad));
  }
  assert.throws(() => S.buildHash("base", "nope"), S.AbiError);
});

test("buildRevokeTx zeroes the allowance on the token contract", () => {
  const tx = S.buildRevokeTx(S.CHAINS.base, { token: TOKEN_A, spender: SPENDER_1 });
  assert.equal(tx.chainId, 8453);
  assert.equal(tx.to, TOKEN_A);
  assert.equal(tx.data, "0x095ea7b3" + SPENDER_1.slice(2).padStart(64, "0") + "0".repeat(64));
  assert.equal(tx.value, "0x0");
});

function mockWallet({ account = OWNER, chainId = 1, rejectSwitch = false, rejectSend = false } = {}) {
  const calls = [];
  let current = chainId;
  return {
    calls,
    async request({ method, params }) {
      calls.push(method);
      if (method === "eth_requestAccounts") return account ? [account] : [];
      if (method === "eth_chainId") return "0x" + current.toString(16);
      if (method === "wallet_switchEthereumChain") {
        if (rejectSwitch) throw new Error("user rejected");
        current = Number(BigInt(params[0].chainId));
        return null;
      }
      if (method === "eth_sendTransaction") {
        if (rejectSend) throw new Error("user rejected");
        assert.equal(params[0].from, account);
        assert.equal(params[0].value, "0x0");
        return "0x" + "ab".repeat(32);
      }
      throw new Error("unexpected " + method);
    },
  };
}
const approval = { owner: OWNER, token: TOKEN_A, spender: SPENDER_1 };

test("sendRevoke succeeds from the owner's wallet", async () => {
  const wallet = mockWallet({ chainId: 1 });
  const hash = await S.sendRevoke(wallet, S.CHAINS.ethereum, approval);
  assert.equal(hash, "0x" + "ab".repeat(32));
  assert.ok(!wallet.calls.includes("wallet_switchEthereumChain"));
});

test("sendRevoke switches chains when needed", async () => {
  const wallet = mockWallet({ chainId: 1 });
  await S.sendRevoke(wallet, S.CHAINS.base, approval);
  assert.deepEqual(wallet.calls, ["eth_requestAccounts", "eth_chainId", "wallet_switchEthereumChain", "eth_chainId", "eth_sendTransaction"]);
});

test("sendRevoke refuses a different connected account and never sends", async () => {
  const wallet = mockWallet({ account: SPENDER_2 });
  await assert.rejects(() => S.sendRevoke(wallet, S.CHAINS.ethereum, approval), /Connect the wallet/);
  assert.ok(!wallet.calls.includes("eth_sendTransaction"));
  const empty = mockWallet({ account: null });
  await assert.rejects(() => S.sendRevoke(empty, S.CHAINS.ethereum, approval), /connected: none/);
});

test("sendRevoke surfaces user rejections and failed chain switches", async () => {
  await assert.rejects(() => S.sendRevoke(mockWallet({ rejectSend: true }), S.CHAINS.ethereum, approval), /user rejected/);
  await assert.rejects(() => S.sendRevoke(mockWallet({ chainId: 1, rejectSwitch: true }), S.CHAINS.base, approval), /user rejected/);
  const stuck = mockWallet({ chainId: 1 });
  const original = stuck.request;
  stuck.request = async (req) => (req.method === "wallet_switchEthereumChain" ? null : original(req));
  await assert.rejects(() => S.sendRevoke(stuck, S.CHAINS.base, approval), /not on base/);
});

// ------------------------------------------------------------------ Solana
const bytes32 = (n) => new Uint8Array(32).fill(n);
const SOL_OWNER = S.b58encode(bytes32(1));
const SOL_MINT = S.b58encode(bytes32(2));
const SOL_ACCT = S.b58encode(bytes32(4));
const SOL_WALLET = S.b58encode(bytes32(7));
const SOL_PROGRAM = S.b58encode(bytes32(8));
const SOL_HASH = S.b58encode(bytes32(9));
function solEntry(pubkey, mint, delegate, amount, decimals = 6) {
  const info = { mint, owner: SOL_OWNER, delegatedAmount: { amount, decimals } };
  if (delegate) info.delegate = delegate;
  return { pubkey, account: { data: { parsed: { info } } } };
}
function solReader(entries, extra = {}) {
  return {
    async call(method, params) {
      if (method === "getTokenAccountsByOwner") {
        return { value: params[1].programId === S.SOLANA.tokenProgram ? entries : [] };
      }
      if (method === "getSlot") return 99;
      if (method === "getLatestBlockhash") return { value: { blockhash: SOL_HASH } };
      if (method === "getAccountInfo") {
        if (extra.failInfo) throw new S.RpcError(-32000, "behind");
        if (params[0] === SOL_PROGRAM) return { value: { executable: true, owner: "Loader" } };
        if (params[0] === SOL_WALLET) return { value: { executable: false, owner: S.SOLANA.systemProgram } };
        return { value: null };
      }
      throw new Error("unexpected " + method);
    },
  };
}

test("base58 known vectors and program ids", () => {
  const enc = (s) => S.b58encode(new TextEncoder().encode(s));
  assert.equal(enc("Hello World!"), "2NEpo7TZRRrLZSi2U");
  assert.deepEqual([...S.b58decode("112")], [0, 0, 1]);
  assert.equal(Buffer.from(S.b58decode(S.SOLANA.tokenProgram)).toString("hex"), "06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9");
  assert.equal(Buffer.from(S.b58decode(S.SOLANA.token2022Program)).toString("hex"), "06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfc");
  for (const bad of ["", "0OIl", null]) assert.throws(() => S.b58decode(bad), S.AbiError);
  assert.ok(S.isSolanaAddress(SOL_OWNER) && !S.isSolanaAddress("0x" + "11".repeat(20)) && !S.isSolanaAddress(S.b58encode(new Uint8Array(31))));
});

test("scanSolana scores delegations like Python", async () => {
  const reader = solReader([
    solEntry(SOL_ACCT, SOL_MINT, SOL_PROGRAM, (2n ** 64n - 1n).toString()),
    solEntry(S.b58encode(bytes32(5)), SOL_MINT, SOL_WALLET, "1500000"),
    solEntry(S.b58encode(bytes32(6)), SOL_MINT, null, "0"),
    solEntry(S.b58encode(bytes32(6)), SOL_MINT, "nope", "5"),
    solEntry(S.b58encode(bytes32(6)), SOL_MINT, SOL_WALLET, "-3"),
    { pubkey: SOL_ACCT },
  ]);
  const out = await S.scanSolana({ reader, rules, owner: SOL_OWNER, nowSec: 5 });
  assert.deepEqual(out.approvals.map((a) => [a.risk.score, a.risk.level]), [[40, "medium"], [30, "medium"]]);
  assert.equal(out.scannedToBlock, 99);
  assert.ok(out.approvals[0].explanation.includes("unlimited") && out.approvals[1].explanation.includes("1.5"));
  assert.ok(out.warnings.some((w) => w.includes("blocklist")));
  await assert.rejects(() => S.scanSolana({ reader, rules, owner: "0x12" }), S.AbiError);
  const down = await S.scanSolana({ reader: solReader([solEntry(SOL_ACCT, SOL_MINT, SOL_WALLET, "5")], { failInfo: true }), rules, owner: SOL_OWNER });
  assert.ok(down.warnings.some((w) => w.includes("Could not tell")));
});

test("unsigned Solana revoke transaction layout", () => {
  const approval = { owner: SOL_OWNER, tokenAccount: SOL_ACCT, tokenProgram: S.SOLANA.tokenProgram };
  const tx = S.buildSolanaRevokeTx(approval, SOL_HASH);
  assert.equal(tx.raw[0], 1);
  assert.ok(tx.raw.slice(1, 65).every((b) => b === 0)); // empty signature: unsigned
  assert.deepEqual([...tx.raw.slice(65, 68)], [1, 0, 1]);
  assert.deepEqual([...tx.raw.slice(-7)], [1, 2, 2, 1, 0, 1, 5]);
  assert.equal(tx.base64, Buffer.from(tx.raw).toString("base64"));
  assert.deepEqual([...S.b58decode(tx.base58)], [...tx.raw]);
  assert.throws(() => S.buildSolanaRevokeTx(approval, S.b58encode(new Uint8Array(5))), S.AbiError);
});

test("sendSolanaRevoke refuses a different connected key and never sends", async () => {
  const approval = { owner: SOL_OWNER, tokenAccount: SOL_ACCT, tokenProgram: S.SOLANA.tokenProgram };
  const calls = [];
  const provider = (key) => ({
    async connect() { return { publicKey: { toString: () => key } }; },
    async request(req) { calls.push(req.method); return { signature: "sig123" }; },
  });
  await assert.rejects(() => S.sendSolanaRevoke(provider(SOL_WALLET), solReader([]), approval), /Connect the wallet/);
  assert.deepEqual(calls, []);
  assert.equal(await S.sendSolanaRevoke(provider(SOL_OWNER), solReader([]), approval), "sig123");
  assert.deepEqual(calls, ["signAndSendTransaction"]);
});

test("solana share links round trip", () => {
  assert.equal(S.buildHash("solana", SOL_OWNER), "#solana:" + SOL_OWNER);
  assert.deepEqual(S.parseHash("#solana:" + SOL_OWNER), { chain: "solana", address: SOL_OWNER });
  for (const bad of ["#solana:abc", "#solana:" + SOL_OWNER + "!", "#solana:0x" + "1".repeat(40)]) assert.equal(S.parseHash(bad), null);
  assert.throws(() => S.buildHash("solana", "0x12"), S.AbiError);
  assert.equal(S.getChain("hood").name, "robinhood");
  assert.equal(S.getChain("solana"), null); // not an EVM chain
});
