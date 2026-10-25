// UI smoke test: serves docs/ statically, mocks every network call, drives report.html in Chromium.
const http = require("http"), fs = require("fs"), path = require("path");
const { chromium } = require("playwright");
const S = require("../../docs/sweepsafe.js");
const root = path.join(__dirname, "../../docs");
const OWNER = "0x" + "11".repeat(20), TOKEN = "0x" + "aa".repeat(20), SPENDER = "0x" + "c1".repeat(20);
const word = (n) => n.toString(16).padStart(64, "0");
const hexStr = (t) => "0x" + word(32) + word(t.length) + Buffer.from(t).toString("hex").padEnd(64, "0");
const HOSTILE = '<img src=x onerror="window.__pwn=1">';

const srv = http.createServer((q, r) => {
  const f = path.join(root, q.url.split("#")[0].split("?")[0].replace(/^\/$/, "/index.html"));
  if (!f.startsWith(root) || !fs.existsSync(f)) { r.writeHead(404); return r.end(); }
  const t = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json" }[path.extname(f)];
  r.writeHead(200, { "content-type": t }); r.end(fs.readFileSync(f));
});

(async () => {
  await new Promise((ok) => srv.listen(0, ok));
  const base = "http://localhost:" + srv.address().port;
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];  page.on("pageerror", (e) => errors.push(String(e)));
  let sent = null;
  await page.addInitScript(([owner]) => {
    window.ethereum = { async request({ method, params }) {
      if (method === "eth_requestAccounts") return [owner];
      if (method === "eth_chainId") return "0x1";
      if (method === "eth_sendTransaction") { window.__tx = params[0]; return "0x" + "ab".repeat(32); }
      throw new Error("unexpected " + method);
    } };
  }, [OWNER]);
  await page.route(/^https:\/\//, async (route) => {
    const req = route.request(), url = req.url();
    const cors = { "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-allow-methods": "*" };
    if (req.method() === "OPTIONS") return route.fulfill({ status: 204, headers: cors });
    if (req.method() === "POST") {
      const { method, params, id } = JSON.parse(req.postData());
      const ok = (result) => route.fulfill({ json: { jsonrpc: "2.0", id, result }, headers: cors });
      if (method === "eth_chainId") return ok("0x1");
      if (method === "eth_blockNumber") return ok("0x3e8");
      if (method === "eth_getLogs") return ok([{ address: TOKEN, topics: [S.APPROVAL_TOPIC, S.addressToTopic(OWNER), S.addressToTopic(SPENDER)],
        data: "0x" + S.encodeUint256((1n << 256n) - 1n), blockNumber: "0x64", logIndex: "0x0", transactionHash: "0x" + "01".repeat(32), removed: false }]);
      if (method === "eth_call") {
        const d = params[0].data.slice(0, 10);
        if (d === S.SELECTORS.allowance) return ok("0x" + S.encodeUint256((1n << 256n) - 1n));
        if (d === S.SELECTORS.symbol) return ok(hexStr(HOSTILE));
        if (d === S.SELECTORS.decimals) return ok("0x" + word(18));
      }
      if (method === "eth_getCode") return ok("0x6080");
      if (method === "eth_getBlockByNumber") return ok({ timestamp: "0x5f5e100" });
      return route.fulfill({ status: 500 });
    }
    return route.fulfill({ status: 404, body: "{}", headers: cors });
  });
  await page.goto(`${base}/report.html#ethereum:${OWNER}`);
  await page.waitForSelector(".card", { timeout: 15000 }).catch(async (e) => { console.error("STATUS:", await page.locator("#status").innerText(), errors); throw e; });
  const text = await page.locator("#results").innerText();
  if (!/unlimited/.test(text)) throw new Error("no unlimited text: " + text);
  if (await page.evaluate(() => window.__pwn)) throw new Error("XSS executed");
  if (await page.locator("#results img").count()) throw new Error("hostile markup became DOM");
  await page.locator("button", { hasText: "Revoke" }).first().click();
  await page.waitForFunction(() => window.__tx);
  const tx = await page.evaluate(() => window.__tx);
  if (tx.to !== TOKEN || !tx.data.startsWith("0x095ea7b3") || !tx.data.endsWith("0".repeat(64))) throw new Error("bad tx " + JSON.stringify(tx));
  await page.goto(base + "/");
  await page.waitForSelector("h1");
  if (errors.length) throw new Error("page errors: " + errors.join("; "));
  console.log("ui smoke ok:", text.split("\n")[0]);
  await browser.close(); srv.close();
})().catch((e) => { console.error(e); process.exit(1); });
