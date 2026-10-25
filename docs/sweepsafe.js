/*
 * SweepSafe web core. Zero dependencies, no CDN scripts, no tracking.
 * Mirrors the Python package (see tests/test_js_parity.py): same constants, rules, templates.
 * It only talks to the RPC and API URLs it is given, and never handles private keys.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.SweepSafe = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // ---------------------------------------------------------------- constants
  const APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
  const SELECTORS = {
    approve: "0x095ea7b3",
    allowance: "0xdd62ed3e",
    symbol: "0x95d89b41",
    decimals: "0x313ce567",
  };
  const MAX_UINT256 = (1n << 256n) - 1n;
  const SOURCIFY_BASE = "https://sourcify.dev/server/v2/contract";
  const BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json",
    "https://raw.githubusercontent.com/MyCryptoHQ/ethereum-lists/master/src/addresses/addresses-darklist.json",
  ];
  const BLOCKLIST_TTL_MS = 86400 * 1000;
  const VERIFIED_TTL_MS = 30 * 86400 * 1000;
  const UNVERIFIED_TTL_MS = 86400 * 1000;
  const MAX_DECIMALS = 77;
  const SECONDS_PER_DAY = 86400;
  const DEFAULT_SCAN = { initialChunk: 100000, minChunk: 250, maxChunk: 5000000, dense: 2000, sparse: 200 };

  const CHAINS = {
    ethereum: {
      name: "ethereum",
      id: 1,
      rpcs: [
        "https://ethereum-rpc.publicnode.com",
        "https://eth.llamarpc.com",
        "https://cloudflare-eth.com",
      ],
      explorer: "https://etherscan.io",
      blockscout: "https://eth.blockscout.com",
      reorgDepth: 64,
      startBlock: 0,
    },
    base: {
      name: "base",
      id: 8453,
      rpcs: [
        "https://base-rpc.publicnode.com",
        "https://mainnet.base.org",
        "https://base.llamarpc.com",
      ],
      explorer: "https://basescan.org",
      blockscout: "https://base.blockscout.com",
      reorgDepth: 256,
      startBlock: 0,
    },
    arbitrum: {
      name: "arbitrum",
      id: 42161,
      rpcs: [
        "https://arbitrum-one-rpc.publicnode.com",
        "https://arb1.arbitrum.io/rpc",
        "https://arbitrum.llamarpc.com",
      ],
      explorer: "https://arbiscan.io",
      blockscout: "https://arbitrum.blockscout.com",
      reorgDepth: 1000,
      startBlock: 0,
    },
    optimism: {
      name: "optimism",
      id: 10,
      rpcs: [
        "https://optimism-rpc.publicnode.com",
        "https://mainnet.optimism.io",
      ],
      explorer: "https://optimistic.etherscan.io",
      blockscout: "https://optimism.blockscout.com",
      reorgDepth: 256,
      startBlock: 0,
    },
    polygon: {
      name: "polygon",
      id: 137,
      rpcs: [
        "https://polygon-bor-rpc.publicnode.com",
        "https://polygon-rpc.com",
      ],
      explorer: "https://polygonscan.com",
      blockscout: "https://polygon.blockscout.com",
      reorgDepth: 256,
      startBlock: 0,
    },
    bnb: {
      name: "bnb",
      id: 56,
      rpcs: [
        "https://bsc-rpc.publicnode.com",
        "https://bsc-dataseed.binance.org",
      ],
      explorer: "https://bscscan.com",
      blockscout: null,
      reorgDepth: 64,
      startBlock: 0,
    },
    avalanche: {
      name: "avalanche",
      id: 43114,
      rpcs: [
        "https://avalanche-c-chain-rpc.publicnode.com",
        "https://api.avax.network/ext/bc/C/rpc",
      ],
      explorer: "https://snowtrace.io",
      blockscout: null,
      reorgDepth: 64,
      startBlock: 0,
    },
    linea: {
      name: "linea",
      id: 59144,
      rpcs: [
        "https://linea-rpc.publicnode.com",
        "https://rpc.linea.build",
      ],
      explorer: "https://lineascan.build",
      blockscout: null,
      reorgDepth: 256,
      startBlock: 0,
    },
    robinhood: {
      name: "robinhood",
      id: 4663,
      rpcs: [
        "https://rpc.mainnet.chain.robinhood.com",
      ],
      explorer: "https://robinhoodchain.blockscout.com",
      blockscout: "https://robinhoodchain.blockscout.com",
      reorgDepth: 256,
      startBlock: 0,
    },
  };
  const ALIASES = {
    eth: "ethereum", mainnet: "ethereum", arb: "arbitrum", "arbitrum-one": "arbitrum",
    op: "optimism", matic: "polygon", bsc: "bnb", "bnb-chain": "bnb", avax: "avalanche",
    "robinhood-chain": "robinhood", hood: "robinhood" };

  // Keep these lists identical to src/sweepsafe/chains/rpc.py (checked by the parity tests).
  const RANGE_HINTS = [
    "block range", "blocks range", "range is too", "range too", "too many results",
    "more than 10000 results", "response size", "query returned more than", "max results",
    "eth_getlogs is limited", "limited to", "exceeds the range", "exceed maximum",
  ];
  const RATE_HINTS = ["rate limit", "too many requests", "429", "capacity", "request limit", "throttl"];
  const REVERT_HINTS = ["revert", "invalid opcode", "out of gas"];

  const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
  const HEX_RE = /^0x[0-9a-fA-F]*$/;

  // ---------------------------------------------------------------- errors
  class AbiError extends Error {}
  class ScanError extends Error {}
  class ChainMismatchError extends Error {}
  class RpcUnavailableError extends Error {}
  class TransportError extends Error {
    constructor(message, opts) {
      super(message);
      this.status = opts && opts.status != null ? opts.status : null;
      this.retriable = opts && opts.retriable != null ? opts.retriable : true;
    }
  }
  class RpcError extends Error {
    constructor(code, message, data) {
      super("RPC error " + code + ": " + message);
      this.code = code;
      this.rpcMessage = String(message);
      this.data = data;
    }
    get isRangeError() {
      const t = this.rpcMessage.toLowerCase();
      return RANGE_HINTS.some((h) => t.includes(h));
    }
    get isRevert() {
      const t = this.rpcMessage.toLowerCase();
      return this.code === 3 || REVERT_HINTS.some((h) => t.includes(h));
    }
    get retriable() {
      if (this.isRangeError || this.isRevert) return false;
      const t = this.rpcMessage.toLowerCase();
      if (RATE_HINTS.some((h) => t.includes(h))) return true;
      return [-32005, -32603, -32000, -32002].includes(this.code);
    }
  }

  // ---------------------------------------------------------------- ABI helpers
  function isAddress(value) {
    return typeof value === "string" && ADDRESS_RE.test(value);
  }
  function normalizeAddress(value) {
    if (!isAddress(value)) throw new AbiError("invalid address: " + String(value));
    return value.toLowerCase();
  }
  function addressToTopic(address) {
    return "0x" + "0".repeat(24) + normalizeAddress(address).slice(2);
  }
  function topicToAddress(topic) {
    if (typeof topic !== "string" || !HEX_RE.test(topic) || topic.length !== 66) {
      throw new AbiError("invalid topic");
    }
    return "0x" + topic.slice(-40).toLowerCase();
  }
  function encodeUint256(value) {
    const v = BigInt(value);
    if (v < 0n || v > MAX_UINT256) throw new AbiError("uint256 out of range");
    return v.toString(16).padStart(64, "0");
  }
  function encodeAllowanceCall(owner, spender) {
    return (
      SELECTORS.allowance +
      normalizeAddress(owner).slice(2).padStart(64, "0") +
      normalizeAddress(spender).slice(2).padStart(64, "0")
    );
  }
  function encodeApprove(spender, amount) {
    return SELECTORS.approve + normalizeAddress(spender).slice(2).padStart(64, "0") + encodeUint256(amount);
  }
  function decodeUint256(data) {
    if (typeof data !== "string" || !HEX_RE.test(data)) throw new AbiError("not hex data");
    if (data.length !== 66) throw new AbiError("expected a single 32-byte word");
    return BigInt(data);
  }
  function hexToInt(value) {
    if (typeof value !== "string" || !HEX_RE.test(value) || value.length < 3) {
      throw new AbiError("invalid quantity: " + String(value));
    }
    return Number(BigInt(value));
  }
  function sanitizeText(text, limit) {
    // Mirrors Python's str.isprintable(): drop control/format/separator characters except " ".
    const kept = Array.from(String(text)).filter(
      (ch) => ch === " " || !/[\p{C}\p{Zl}\p{Zp}\p{Zs}]/u.test(ch)
    );
    return Array.from(kept.join("").trim()).slice(0, limit || 32).join("");
  }
  function hexToBytes(hex) {
    const body = hex.slice(2);
    const out = new Uint8Array(body.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(body.slice(2 * i, 2 * i + 2), 16);
    return out;
  }
  function bytesToBigInt(bytes) {
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    return n;
  }
  /** Decode a token symbol() result (ABI string or legacy bytes32); null if uninterpretable. */
  function decodeString(data) {
    if (typeof data !== "string" || !HEX_RE.test(data) || data.length % 2 !== 0) return null;
    const raw = hexToBytes(data);
    const decoder = new TextDecoder("utf-8");
    let text;
    if (raw.length === 32) {
      let end = raw.length;
      while (end > 0 && raw[end - 1] === 0) end--;
      text = decoder.decode(raw.slice(0, end));
    } else if (raw.length >= 64) {
      const offset = bytesToBigInt(raw.slice(0, 32));
      if (offset + 32n > BigInt(raw.length)) return null;
      const off = Number(offset);
      const length = bytesToBigInt(raw.slice(off, off + 32));
      const start = off + 32;
      if (length > 1024n || BigInt(start) + length > BigInt(raw.length)) return null;
      text = decoder.decode(raw.slice(start, start + Number(length)));
    } else {
      return null;
    }
    const cleaned = sanitizeText(text, 32);
    return cleaned || null;
  }

  // ---------------------------------------------------------------- formatting
  function shortAddress(address) {
    return address.slice(0, 6) + "…" + address.slice(-4);
  }
  /** Integer-only maths (BigInt) so the text matches the Python implementation exactly. */
  function formatAmount(value, decimals, unlimitedThreshold) {
    const v = BigInt(value);
    if (v >= BigInt(unlimitedThreshold)) return "unlimited";
    if (decimals === null || decimals === undefined || decimals < 0 || decimals > MAX_DECIMALS) {
      return v.toString() + " raw units";
    }
    const scale = 10n ** BigInt(decimals);
    const whole = v / scale;
    const frac = v % scale;
    const fracText = decimals > 0 ? frac.toString().padStart(decimals, "0").slice(0, 4).replace(/0+$/, "") : "";
    if (whole === 0n && v > 0n && !fracText) return "<0.0001";
    return whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",") + (fracText ? "." + fracText : "");
  }

  // ---------------------------------------------------------------- rules + explanations
  function parseRules(json) {
    const rules = typeof json === "string" ? JSON.parse(json) : json;
    return {
      version: rules.version,
      unlimitedThreshold: BigInt(rules.unlimited_threshold),
      staleDays: rules.stale_days,
      rules: rules.rules,
      levels: rules.levels.slice().sort((a, b) => b.min - a.min),
      explain: rules.explain,
    };
  }
  function levelFor(rules, score) {
    for (const level of rules.levels) if (score >= level.min) return level.name;
    return rules.levels[rules.levels.length - 1].name;
  }
  function ageInDays(timestamp, now) {
    if (timestamp === null || timestamp === undefined) return null;
    return Math.max(0, Math.floor((now - timestamp) / SECONDS_PER_DAY));
  }
  // Order matters: it must match BUILTIN_RULES in src/sweepsafe/risk/engine.py.
  const BUILTIN_RULES = [
    ["blocklisted_spender", (i) => i.blocklisted === true],
    ["spender_is_eoa", (i) => i.spender_is_contract === false],
    ["unlimited_allowance", (i, r) => BigInt(i.allowance) >= r.unlimitedThreshold],
    ["unverified_contract", (i) => i.spender_is_contract === true && i.verification === "unverified"],
    ["unknown_verification", (i) => i.spender_is_contract === true && i.verification === "unknown"],
    [
      "stale_approval",
      (i, r) => i.age_days !== null && i.age_days !== undefined && i.age_days > r.staleDays,
    ],
  ];
  function evaluateRisk(rules, input) {
    const findings = [];
    for (const [id, applies] of BUILTIN_RULES) {
      const spec = rules.rules[id];
      if (!spec || !applies(input, rules)) continue;
      const message = id === "stale_approval" ? spec.message.split("{days}").join(String(input.age_days)) : spec.message;
      findings.push({ rule_id: id, weight: spec.weight, message });
    }
    const score = Math.min(100, findings.reduce((sum, f) => sum + f.weight, 0));
    return { score, level: levelFor(rules, score), findings };
  }
  /** Single-pass substitution so hostile values (e.g. a token symbol "{spender}") stay inert. */
  function fillTemplate(template, values) {
    return template.replace(/\{(\w+)\}/g, (m, key) =>
      Object.prototype.hasOwnProperty.call(values, key) ? values[key] : m
    );
  }
  function tokenLabel(approval) {
    return approval.tokenSymbol || "Token " + shortAddress(approval.token);
  }
  function explainApproval(rules, approval, risk) {
    const values = {
      symbol: tokenLabel(approval),
      allowance: formatAmount(approval.allowance, approval.tokenDecimals, rules.unlimitedThreshold),
      spender: shortAddress(approval.spender),
      level: risk.level,
      score: String(risk.score),
    };
    const lines = [fillTemplate(rules.explain.headline, values), fillTemplate(rules.explain.risk_line, values)];
    if (risk.findings.length) for (const f of risk.findings) lines.push("- " + f.message);
    else lines.push("- " + rules.explain.no_findings);
    lines.push(rules.explain.advice[risk.level] || "");
    return lines.filter(Boolean).join("\n");
  }

  // ---------------------------------------------------------------- HTTP + RPC
  function checkUrl(url) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (e) {
      throw new TransportError("refusing invalid URL: " + url, { retriable: false });
    }
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
    if (parsed.protocol === "https:" || (parsed.protocol === "http:" && local)) return;
    throw new TransportError("refusing non-HTTPS URL: " + url, { retriable: false });
  }

  function defaultFetch() {
    return typeof fetch === "function" ? fetch.bind(globalThis) : null;
  }

  async function withTimeout(fetchImpl, url, init, timeoutMs) {
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    try {
      return await fetchImpl(url, controller ? Object.assign({}, init, { signal: controller.signal }) : init);
    } catch (e) {
      throw new TransportError("network error for " + url + ": " + (e && e.message ? e.message : e));
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** GET JSON; throws TransportError with .status on HTTP errors (404 is not retriable). */
  async function getJson(fetchImpl, url, timeoutMs) {
    checkUrl(url);
    const res = await withTimeout(fetchImpl, url, { method: "GET", headers: { accept: "application/json" } }, timeoutMs || 20000);
    if (!res.ok) {
      throw new TransportError("HTTP " + res.status + " from " + url, {
        status: res.status,
        retriable: res.status === 429 || res.status >= 500,
      });
    }
    try {
      return await res.json();
    } catch (e) {
      throw new TransportError("invalid JSON from " + url);
    }
  }

  function createRpc(options) {
    const opts = options || {};
    const urls = (opts.urls || []).slice();
    if (!urls.length) throw new Error("at least one RPC URL is required");
    urls.forEach(checkUrl);
    const fetchImpl = opts.fetch || defaultFetch();
    const sleep = opts.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
    const now = opts.now || (() => Date.now());
    const retries = opts.retries != null ? opts.retries : 3;
    const backoffMs = opts.backoffMs != null ? opts.backoffMs : 750;
    const minIntervalMs = opts.minIntervalMs != null ? opts.minIntervalMs : 150;
    const timeoutMs = opts.timeoutMs != null ? opts.timeoutMs : 20000;
    const expectedChainId = opts.expectedChainId != null ? opts.expectedChainId : null;
    let index = 0;
    let nextId = 1;
    let last = -Infinity;
    const verified = new Set();
    const bad = new Set();

    function rotate() {
      for (let step = 1; step <= urls.length; step++) {
        const candidate = (index + step) % urls.length;
        if (!bad.has(urls[candidate])) {
          index = candidate;
          return;
        }
      }
    }

    async function request(url, method, params) {
      const wait = minIntervalMs - (now() - last);
      if (wait > 0) await sleep(wait);
      last = now();
      const payload = { jsonrpc: "2.0", id: nextId++, method, params };
      const res = await withTimeout(
        fetchImpl,
        url,
        { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) },
        timeoutMs
      );
      if (!res.ok) {
        throw new TransportError("HTTP " + res.status + " from " + url, {
          status: res.status,
          retriable: res.status === 429 || res.status >= 500,
        });
      }
      let body;
      try {
        body = await res.json();
      } catch (e) {
        throw new TransportError("invalid JSON from " + url);
      }
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        throw new TransportError("malformed JSON-RPC response from " + url);
      }
      if (body.error !== undefined && body.error !== null) {
        const err = body.error;
        if (typeof err === "object") throw new RpcError(Number(err.code != null ? err.code : -32000), err.message || "", err.data);
        throw new RpcError(-32000, String(err));
      }
      if (!("result" in body)) throw new TransportError("JSON-RPC response from " + url + " has no result");
      return body.result;
    }

    async function ensureChain(url) {
      if (expectedChainId === null || verified.has(url)) return;
      const actual = hexToInt(await request(url, "eth_chainId", []));
      if (actual !== expectedChainId) {
        bad.add(url);
        throw new ChainMismatchError(url + " is chain " + actual + ", expected " + expectedChainId);
      }
      verified.add(url);
    }

    async function call(method, params) {
      const attempts = Math.max(retries + 1, 1);
      let lastError = null;
      for (let attempt = 0; attempt < attempts; attempt++) {
        if (urls.every((u) => bad.has(u))) {
          throw new ChainMismatchError("no RPC provider serves chain " + expectedChainId);
        }
        const url = urls[index];
        let mismatch = false;
        try {
          await ensureChain(url);
          return await request(url, method, params || []);
        } catch (e) {
          if (e instanceof ChainMismatchError) {
            lastError = e;
            mismatch = true;
          } else if ((e instanceof RpcError || e instanceof TransportError) && e.retriable) {
            lastError = e;
          } else {
            throw e;
          }
        }
        rotate();
        if (!mismatch && attempt < attempts - 1) await sleep(backoffMs * Math.pow(2, attempt));
      }
      throw new RpcUnavailableError("all RPC attempts failed for " + method + ": " + (lastError && lastError.message));
    }

    return {
      call,
      get urls() {
        return urls.slice();
      },
      async blockNumber() {
        return hexToInt(await call("eth_blockNumber"));
      },
      async getLogs(fromBlock, toBlock, topics) {
        const result = await call("eth_getLogs", [
          { fromBlock: "0x" + fromBlock.toString(16), toBlock: "0x" + toBlock.toString(16), topics },
        ]);
        if (!Array.isArray(result)) throw new TransportError("eth_getLogs returned a non-list result");
        return result;
      },
      async ethCall(to, data) {
        const result = await call("eth_call", [{ to, data }, "latest"]);
        if (typeof result !== "string") throw new TransportError("eth_call returned a non-string result");
        return result;
      },
      async getCode(address) {
        const result = await call("eth_getCode", [address, "latest"]);
        if (typeof result !== "string") throw new TransportError("eth_getCode returned a non-string result");
        return result;
      },
      async getBlockTimestamp(blockNumber) {
        const block = await call("eth_getBlockByNumber", ["0x" + blockNumber.toString(16), false]);
        if (!block || typeof block !== "object" || !("timestamp" in block)) {
          throw new TransportError("block " + blockNumber + " not available");
        }
        return hexToInt(block.timestamp);
      },
    };
  }

  // ---------------------------------------------------------------- chains
  function getChain(name) {
    const key = String(name || "").trim().toLowerCase();
    return CHAINS[ALIASES[key] || key] || null;
  }

  // ---------------------------------------------------------------- log scanning
  /** ERC-20 only: ERC-721 Approval events share topic0 but carry four topics. */
  function parseApprovalLog(entry, owner) {
    try {
      if (!entry || entry.removed) return null;
      const topics = entry.topics;
      if (!Array.isArray(topics) || topics.length !== 3 || String(topics[0]).toLowerCase() !== APPROVAL_TOPIC) return null;
      if (topicToAddress(topics[1]) !== owner) return null;
      const data = entry.data;
      if (typeof data !== "string" || data.length !== 66 || !HEX_RE.test(data)) return null;
      return {
        token: normalizeAddress(entry.address),
        spender: topicToAddress(topics[2]),
        value: BigInt(data),
        blockNumber: hexToInt(entry.blockNumber),
        logIndex: hexToInt(entry.logIndex),
        txHash: String(entry.transactionHash).toLowerCase(),
      };
    } catch (e) {
      return null;
    }
  }

  async function fetchApprovalLogs(reader, owner, fromBlock, toBlock, options) {
    const o = Object.assign({}, DEFAULT_SCAN, options || {});
    owner = normalizeAddress(owner);
    const topics = [APPROVAL_TOPIC, addressToTopic(owner)];
    let chunk = Math.max(o.minChunk, Math.min(o.initialChunk, o.maxChunk));
    let start = fromBlock;
    while (start <= toBlock) {
      const end = Math.min(start + chunk - 1, toBlock);
      let raw;
      try {
        raw = await reader.getLogs(start, end, topics);
      } catch (e) {
        if (e instanceof RpcError && e.isRangeError) {
          if (chunk > o.minChunk) {
            chunk = Math.max(o.minChunk, Math.floor(chunk / 2));
            continue;
          }
          throw new ScanError("node rejects even a " + o.minChunk + "-block range (blocks " + start + "-" + end + "): " + e.rpcMessage);
        }
        throw e;
      }
      const logs = raw.map((entry) => parseApprovalLog(entry, owner)).filter(Boolean);
      if (o.onChunk) await o.onChunk(start, end, logs);
      if (o.onProgress) o.onProgress(end, toBlock);
      start = end + 1;
      if (raw.length >= o.dense) chunk = Math.max(o.minChunk, Math.floor(chunk / 2));
      else if (raw.length < o.sparse) chunk = Math.min(o.maxChunk, chunk * 2);
    }
  }

  // ---------------------------------------------------------------- caches (all best-effort)
  function memoryCache() {
    const map = new Map();
    return {
      get: (key) => (map.has(key) ? map.get(key) : null),
      set: (key, value) => void map.set(key, value),
    };
  }
  /** localStorage-backed cache. Storage can be missing, full, or blocked: never let it break a scan. */
  function storageCache(storage) {
    const fallback = memoryCache();
    return {
      get(key) {
        try {
          const raw = storage.getItem(key);
          return raw === null ? fallback.get(key) : JSON.parse(raw);
        } catch (e) {
          return fallback.get(key);
        }
      },
      set(key, value) {
        fallback.set(key, value);
        try {
          storage.setItem(key, JSON.stringify(value));
        } catch (e) {
          /* quota exceeded or blocked: in-memory copy is still used */
        }
      },
    };
  }
  function serializeLogs(logs) {
    return logs.map((l) => Object.assign({}, l, { value: l.value.toString() }));
  }
  function deserializeLogs(logs) {
    return logs.map((l) => Object.assign({}, l, { value: BigInt(l.value) }));
  }

  async function syncLogs(args) {
    const { reader, chain, cache } = args;
    const owner = normalizeAddress(args.owner);
    const key = "sweepsafe:v1:logs:" + chain.name + ":" + owner;
    const warnings = [];
    const head = await reader.blockNumber();
    let state = args.reset || !cache ? null : cache.get(key);
    const requestedStart = args.fromBlock == null ? chain.startBlock : Math.max(0, args.fromBlock);
    if (state && requestedStart < state.firstBlock) state = null;

    let firstBlock;
    let start;
    let logs;
    if (!state) {
      firstBlock = start = requestedStart;
      logs = [];
    } else {
      firstBlock = state.firstBlock;
      // Re-scan the tail so a shallow reorg cannot leave logs from orphaned blocks behind.
      start = Math.max(firstBlock, state.lastBlock - chain.reorgDepth + 1);
      logs = deserializeLogs(state.logs).filter((l) => l.blockNumber < start);
    }
    if (firstBlock > chain.startBlock) {
      warnings.push("History before block " + firstBlock + " was not scanned; approvals granted earlier will not appear.");
    }
    if (start > head) {
      return { logs: state ? deserializeLogs(state.logs) : [], scannedTo: state ? state.lastBlock : head, warnings };
    }
    let chunks = 0;
    const persist = (lastBlock) => {
      if (cache) cache.set(key, { firstBlock, lastBlock, logs: serializeLogs(logs) });
    };
    let lastChunkEnd = start - 1;
    await fetchApprovalLogs(reader, owner, start, head, {
      onProgress: args.onProgress,
      onChunk: (from, to, chunkLogs) => {
        logs.push(...chunkLogs);
        lastChunkEnd = to;
        chunks++;
        if (chunks % 10 === 0) persist(to);
      },
    });
    persist(lastChunkEnd);
    return { logs, scannedTo: head, warnings };
  }

  // ---------------------------------------------------------------- approvals
  async function activeApprovals(args) {
    const { reader, chain } = args;
    const owner = normalizeAddress(args.owner);
    const warnings = [];
    const latest = new Map();
    for (const log of args.logs) {
      const key = log.token + ":" + log.spender;
      const prev = latest.get(key);
      if (!prev || log.blockNumber > prev.blockNumber || (log.blockNumber === prev.blockNumber && log.logIndex > prev.logIndex)) {
        latest.set(key, log);
      }
    }
    const ordered = Array.from(latest.values()).sort((a, b) => a.blockNumber - b.blockNumber || a.logIndex - b.logIndex);
    const metaCache = new Map();
    const tsCache = new Map();
    const approvals = [];

    async function tokenMeta(token) {
      if (metaCache.has(token)) return metaCache.get(token);
      let symbol = null;
      let decimals = null;
      try {
        symbol = decodeString(await reader.ethCall(token, SELECTORS.symbol));
      } catch (e) {
        if (!(e instanceof RpcError)) throw e;
      }
      try {
        const value = decodeUint256(await reader.ethCall(token, SELECTORS.decimals));
        decimals = value <= 255n ? Number(value) : null;
      } catch (e) {
        if (!(e instanceof RpcError || e instanceof AbiError)) throw e;
      }
      const meta = { symbol, decimals };
      metaCache.set(token, meta);
      return meta;
    }
    async function blockTimestamp(blockNumber) {
      if (tsCache.has(blockNumber)) return tsCache.get(blockNumber);
      try {
        const ts = await reader.getBlockTimestamp(blockNumber);
        tsCache.set(blockNumber, ts);
        return ts;
      } catch (e) {
        warnings.push("Could not read the date of block " + blockNumber + ".");
        tsCache.set(blockNumber, null);
        return null;
      }
    }

    for (const log of ordered) {
      if (log.value === 0n) continue; // the last event set it to zero
      let allowance;
      try {
        allowance = decodeUint256(await reader.ethCall(log.token, encodeAllowanceCall(owner, log.spender)));
      } catch (e) {
        if (e instanceof RpcError || e instanceof AbiError) {
          warnings.push("Could not read allowance for token " + log.token + "; skipped.");
          continue;
        }
        throw e;
      }
      if (allowance === 0n) continue; // spent down without an event
      const meta = await tokenMeta(log.token);
      approvals.push({
        chain: chain.name,
        owner,
        token: log.token,
        spender: log.spender,
        allowance,
        blockNumber: log.blockNumber,
        txHash: log.txHash,
        timestamp: await blockTimestamp(log.blockNumber),
        tokenSymbol: meta.symbol,
        tokenDecimals: meta.decimals,
        spenderIsContract: null,
        verification: "unknown",
        blocklisted: false,
      });
    }
    return { approvals, warnings };
  }

  function isContractCode(code) {
    const lowered = String(code).toLowerCase();
    if (lowered === "" || lowered === "0x" || lowered === "0x0") return false;
    return !(lowered.startsWith("0xef0100") && lowered.length === 2 + 23 * 2); // EIP-7702 delegated wallet
  }
  async function classifySpender(reader, address) {
    try {
      return isContractCode(await reader.getCode(address));
    } catch (e) {
      if (e instanceof RpcError || e instanceof TransportError || e instanceof RpcUnavailableError) return null;
      throw e;
    }
  }

  // ---------------------------------------------------------------- blocklist + verification
  function parseAddressList(data) {
    const found = new Set();
    const skip = ["white", "allow", "safe", "trusted"];
    (function walk(node) {
      if (typeof node === "string") {
        if (isAddress(node)) found.add(node.toLowerCase());
      } else if (Array.isArray(node)) {
        node.forEach(walk);
      } else if (node && typeof node === "object") {
        for (const [k, v] of Object.entries(node)) {
          if (skip.some((m) => k.toLowerCase().includes(m))) continue;
          walk(v);
        }
      }
    })(data);
    return found;
  }

  async function loadBlocklist(args) {
    const { fetchImpl, cache } = args;
    const urls = args.urls || BLOCKLIST_URLS;
    const now = typeof args.now === "function" ? args.now() : args.now != null ? args.now : Date.now();
    const merged = new Set();
    const warnings = [];
    for (const url of urls) {
      const key = "sweepsafe:v1:blocklist:" + url;
      const cached = cache ? cache.get(key) : null;
      if (cached && now - cached.fetchedAt <= BLOCKLIST_TTL_MS) {
        cached.addresses.forEach((a) => merged.add(a));
        continue;
      }
      try {
        const addresses = parseAddressList(await getJson(fetchImpl, url, args.timeoutMs));
        if (cache) cache.set(key, { fetchedAt: now, addresses: Array.from(addresses) });
        addresses.forEach((a) => merged.add(a));
      } catch (e) {
        if (cached) {
          cached.addresses.forEach((a) => merged.add(a));
          warnings.push("Blocklist source could not be refreshed, using cached copy: " + url);
        } else {
          warnings.push("Blocklist source unavailable (no cached copy): " + url);
        }
      }
    }
    return { addresses: merged, warnings };
  }

  async function providerCheck(fetchImpl, url, interpret, timeoutMs) {
    try {
      return interpret(await getJson(fetchImpl, url, timeoutMs));
    } catch (e) {
      if (e instanceof TransportError) return e.status === 404 ? "unverified" : "unknown";
      throw e;
    }
  }
  /** Verified anywhere wins; unverified only when someone answered definitively; else unknown. */
  async function checkVerification(args) {
    const { fetchImpl, chain, cache } = args;
    const address = normalizeAddress(args.address);
    const now = typeof args.now === "function" ? args.now() : args.now != null ? args.now : Date.now();
    const key = "sweepsafe:v1:verify:" + chain.id + ":" + address;
    const cached = cache ? cache.get(key) : null;
    if (cached) {
      const ttl = cached.status === "verified" ? VERIFIED_TTL_MS : UNVERIFIED_TTL_MS;
      if (now - cached.at <= ttl) return cached.status;
    }
    const answers = [];
    answers.push(
      await providerCheck(fetchImpl, SOURCIFY_BASE + "/" + chain.id + "/" + address,
        (body) => (body && typeof body === "object" && Object.keys(body).length ? "verified" : "unknown"), args.timeoutMs)
    );
    if (answers[0] !== "verified" && chain.blockscout) {
      answers.push(
        await providerCheck(fetchImpl, chain.blockscout + "/api/v2/smart-contracts/" + address,
          (body) => (body && typeof body === "object" && !Array.isArray(body) ? (body.is_verified === true ? "verified" : "unverified") : "unknown"),
          args.timeoutMs)
      );
    }
    const status = answers.includes("verified") ? "verified" : answers.includes("unverified") ? "unverified" : "unknown";
    if (cache && status !== "unknown") cache.set(key, { status, at: now });
    return status;
  }

  // ---------------------------------------------------------------- orchestration
  async function scanWallet(args) {
    const { reader, chain, rules, fetchImpl } = args;
    const owner = normalizeAddress(args.owner);
    const nowSec = args.nowSec != null ? args.nowSec : Math.floor(Date.now() / 1000);
    const sync = await syncLogs({
      reader, chain, owner, cache: args.cache, fromBlock: args.fromBlock, reset: args.reset, onProgress: args.onProgress,
    });
    const active = await activeApprovals({ reader, chain, owner, logs: sync.logs });
    const warnings = sync.warnings.concat(active.warnings);
    const blocklist = args.blocklist || { addresses: new Set(), warnings: [] };
    warnings.push(...blocklist.warnings);

    const kinds = new Map();
    const scored = [];
    for (const approval of active.approvals) {
      if (!kinds.has(approval.spender)) {
        const kind = await classifySpender(reader, approval.spender);
        kinds.set(approval.spender, kind);
        if (kind === null) warnings.push("Could not tell whether spender " + approval.spender + " is a contract.");
      }
      approval.spenderIsContract = kinds.get(approval.spender);
      approval.blocklisted = blocklist.addresses.has(approval.spender);
      approval.verification = approval.spenderIsContract
        ? await checkVerification({ fetchImpl, chain, address: approval.spender, cache: args.cache, now: args.nowSec != null ? args.nowSec * 1000 : undefined })
        : "unknown";
      const risk = evaluateRisk(rules, {
        allowance: approval.allowance,
        spender_is_contract: approval.spenderIsContract,
        verification: approval.verification,
        blocklisted: approval.blocklisted,
        age_days: ageInDays(approval.timestamp, nowSec),
      });
      scored.push({ approval, risk, explanation: explainApproval(rules, approval, risk) });
    }
    scored.sort((a, b) =>
      b.risk.score - a.risk.score ||
      (a.approval.token < b.approval.token ? -1 : a.approval.token > b.approval.token ? 1 : 0) ||
      (a.approval.spender < b.approval.spender ? -1 : a.approval.spender > b.approval.spender ? 1 : 0));
    return {
      chain: chain.name,
      chainId: chain.id,
      owner,
      scannedToBlock: sync.scannedTo,
      generatedAt: nowSec,
      approvals: scored,
      warnings,
    };
  }


  // ---------------------------------------------------------------- Solana (SPL token delegations)
  const SOLANA = {
    name: "solana",
    clusterId: 101,
    rpcs: ["https://solana-rpc.publicnode.com", "https://api.mainnet-beta.solana.com"],
    explorer: "https://solscan.io",
    tokenProgram: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    token2022Program: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    systemProgram: "11111111111111111111111111111111",
  };
  const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const U64_HALF = 1n << 63n;

  function b58encode(bytes) {
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    let out = "";
    while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
    return "1".repeat(zeros) + out;
  }
  function b58decode(text) {
    if (typeof text !== "string" || !text) throw new AbiError("empty base58 string");
    let n = 0n;
    for (const c of text) {
      const i = B58.indexOf(c);
      if (i < 0) throw new AbiError("invalid base58 character");
      n = n * 58n + BigInt(i);
    }
    const bytes = [];
    while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
    let zeros = 0;
    while (zeros < text.length && text[zeros] === "1") zeros++;
    return Uint8Array.from([...new Array(zeros).fill(0), ...bytes]);
  }
  function isSolanaAddress(value) {
    if (typeof value !== "string" || value.length < 32 || value.length > 44) return false;
    try { return b58decode(value).length === 32; } catch (e) { return false; }
  }
  function toBase64(bytes) {
    if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }
  function compactU16(n) {
    const out = [];
    for (;;) {
      const byte = n & 0x7f;
      n >>= 7;
      if (n) out.push(byte | 0x80); else { out.push(byte); return out; }
    }
  }

  function parseSolanaAccount(entry, owner, program) {
    try {
      const info = entry.account.data.parsed.info;
      const delegate = info.delegate;
      if (!delegate || !isSolanaAddress(delegate)) return null;
      if (!/^[0-9]+$/.test(String(info.delegatedAmount.amount))) return null;
      const delegated = BigInt(info.delegatedAmount.amount);
      if (delegated <= 0n) return null;
      if (!isSolanaAddress(info.mint) || !isSolanaAddress(entry.pubkey)) return null;
      const d = info.delegatedAmount.decimals;
      return {
        chain: "solana", owner, token: info.mint, spender: delegate,
        allowance: delegated >= U64_HALF ? MAX_UINT256 : delegated,
        tokenSymbol: null,
        tokenDecimals: Number.isInteger(d) && d >= 0 && d <= MAX_DECIMALS ? d : null,
        tokenAccount: entry.pubkey, tokenProgram: program,
        timestamp: null, spenderIsContract: null, verification: "unknown", blocklisted: false,
      };
    } catch (e) {
      return null;
    }
  }
  async function isSolanaProgram(reader, address) {
    try {
      const res = await reader.call("getAccountInfo", [address, { encoding: "base64", dataSlice: { offset: 0, length: 0 } }]);
      const account = res && res.value;
      if (!account) return false;
      if (account.executable === true) return true;
      return account.owner === SOLANA.systemProgram ? false : null;
    } catch (e) {
      return null;
    }
  }
  async function scanSolana(args) {
    const { reader, rules } = args;
    const owner = args.owner;
    if (!isSolanaAddress(owner)) throw new AbiError("not a valid Solana address");
    const warnings = [
      "Solana: no public scam-address list is configured, so blocklist checks are skipped.",
      "Solana: program source verification is not available, so programs show as unknown.",
    ];
    const approvals = [];
    for (const program of [SOLANA.tokenProgram, SOLANA.token2022Program]) {
      const res = await reader.call("getTokenAccountsByOwner", [owner, { programId: program }, { encoding: "jsonParsed" }]);
      if (!res || !Array.isArray(res.value)) throw new TransportError("getTokenAccountsByOwner returned an unexpected shape");
      for (const entry of res.value) {
        const a = parseSolanaAccount(entry, owner, program);
        if (a) approvals.push(a);
      }
    }
    const slot = await reader.call("getSlot", []);
    const kinds = new Map();
    const scored = [];
    for (const a of approvals) {
      if (!kinds.has(a.spender)) {
        kinds.set(a.spender, await isSolanaProgram(reader, a.spender));
        if (kinds.get(a.spender) === null) warnings.push("Could not tell what kind of account " + a.spender + " is.");
      }
      a.spenderIsContract = kinds.get(a.spender);
      const risk = evaluateRisk(rules, {
        allowance: a.allowance, spender_is_contract: a.spenderIsContract,
        verification: "unknown", blocklisted: false, age_days: null,
      });
      scored.push({ approval: a, risk, explanation: explainApproval(rules, a, risk) });
    }
    scored.sort((x, y) => y.risk.score - x.risk.score || (x.approval.token < y.approval.token ? -1 : x.approval.token > y.approval.token ? 1 : x.approval.spender < y.approval.spender ? -1 : 1));
    return {
      chain: "solana", owner, scannedToBlock: Number.isInteger(slot) ? slot : 0,
      generatedAt: args.nowSec != null ? args.nowSec : Math.floor(Date.now() / 1000),
      approvals: scored, warnings,
    };
  }
  /** Unsigned legacy transaction (one empty signature slot) revoking the delegate. */
  function buildSolanaRevokeTx(approval, blockhash) {
    const keys = [approval.owner, approval.tokenAccount, approval.tokenProgram].map(b58decode);
    const recent = b58decode(blockhash);
    if (keys.some((k) => k.length !== 32) || recent.length !== 32) throw new AbiError("addresses and blockhash must be 32 bytes");
    const message = [1, 0, 1, ...compactU16(3)];
    for (const k of keys) message.push(...k);
    message.push(...recent, ...compactU16(1), 2, ...compactU16(2), 1, 0, ...compactU16(1), 5);
    const raw = Uint8Array.from([...compactU16(1), ...new Array(64).fill(0), ...message]);
    return { raw, base64: toBase64(raw), base58: b58encode(raw) };
  }
  /** Phantom-style provider. Refuses unless the connected key IS the scanned owner. */
  async function sendSolanaRevoke(provider, reader, approval) {
    const resp = await provider.connect();
    const key = String((resp && resp.publicKey) || provider.publicKey || "");
    if (key !== approval.owner) {
      throw new Error("Connect the wallet " + shortAddress(approval.owner) + " to revoke this delegation (connected: " + (key ? shortAddress(key) : "none") + ").");
    }
    const latest = await reader.call("getLatestBlockhash", [{ commitment: "confirmed" }]);
    const tx = buildSolanaRevokeTx(approval, latest.value.blockhash);
    const sent = await provider.request({ method: "signAndSendTransaction", params: { message: tx.base58 } });
    return sent && sent.signature ? sent.signature : sent;
  }

  // ---------------------------------------------------------------- share links + revoke
  function buildHash(chainName, address) {
    if (chainName === "solana") {
      if (!isSolanaAddress(address)) throw new AbiError("not a valid Solana address");
      return "#solana:" + address;
    }
    return "#" + chainName + ":" + normalizeAddress(address);
  }
  /** "#base:0xabc..." -> {chain, address} or null. Anything malformed is rejected. */
  function parseHash(hash) {
    const text = String(hash || "").trim();
    const sol = /^#?solana:([1-9A-HJ-NP-Za-km-z]{32,44})$/.exec(text);
    if (sol) return isSolanaAddress(sol[1]) ? { chain: "solana", address: sol[1] } : null;
    const m = /^#?([a-z0-9-]{2,20}):(0x[0-9a-fA-F]{40})$/.exec(text);
    if (!m) return null;
    const chain = getChain(m[1]);
    return chain ? { chain: chain.name, address: m[2].toLowerCase() } : null;
  }
  function buildRevokeTx(chain, approval) {
    return {
      chainId: chain.id,
      to: normalizeAddress(approval.token),
      data: encodeApprove(approval.spender, 0n),
      value: "0x0",
    };
  }

  /**
   * Send a revoke from the user's own wallet. Refuses unless the connected account IS the scanned
   * owner: approve() changes the allowance of whoever sends it, so any other account would
   * revoke the wrong thing.
   */
  async function sendRevoke(ethereum, chain, approval) {
    const accounts = await ethereum.request({ method: "eth_requestAccounts" });
    const account = String(accounts && accounts[0] || "").toLowerCase();
    if (account !== approval.owner) {
      throw new Error("Connect the wallet " + shortAddress(approval.owner) + " to revoke this approval (connected: " + (account ? shortAddress(account) : "none") + ").");
    }
    const current = hexToInt(await ethereum.request({ method: "eth_chainId" }));
    if (current !== chain.id) {
      await ethereum.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x" + chain.id.toString(16) }] });
      const after = hexToInt(await ethereum.request({ method: "eth_chainId" }));
      if (after !== chain.id) throw new Error("Wallet is not on " + chain.name + ".");
    }
    const tx = buildRevokeTx(chain, approval);
    return ethereum.request({
      method: "eth_sendTransaction",
      params: [{ from: account, to: tx.to, data: tx.data, value: tx.value }],
    });
  }

  return {
    APPROVAL_TOPIC, SELECTORS, MAX_UINT256, CHAINS, SOLANA,
    b58encode, b58decode, isSolanaAddress, scanSolana, buildSolanaRevokeTx, sendSolanaRevoke, parseSolanaAccount, BLOCKLIST_URLS, SOURCIFY_BASE,
    RANGE_HINTS, RATE_HINTS, REVERT_HINTS,
    AbiError, ScanError, ChainMismatchError, RpcUnavailableError, TransportError, RpcError,
    isAddress, normalizeAddress, addressToTopic, topicToAddress, encodeUint256, encodeAllowanceCall,
    encodeApprove, decodeUint256, decodeString, sanitizeText, hexToInt,
    shortAddress, formatAmount, parseRules, levelFor, ageInDays, evaluateRisk, fillTemplate,
    explainApproval, tokenLabel, checkUrl, getJson, createRpc, getChain, parseApprovalLog,
    fetchApprovalLogs, memoryCache, storageCache, syncLogs, activeApprovals, isContractCode,
    classifySpender, parseAddressList, loadBlocklist, checkVerification, scanWallet, buildHash,
    parseHash, buildRevokeTx, sendRevoke,
  };
});
