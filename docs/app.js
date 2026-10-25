(function () {
  "use strict";
  var S = window.SweepSafe;
  var $ = function (id) { return document.getElementById(id); };
  var W = window.SweepSafeWallets;
  var wallets = W.init(window, S);
  var state = { rules: null, wallet: null, scanning: false };

  function setStatus(text) { $("status").textContent = text; }
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text; // textContent only: token metadata is hostile
    return n;
  }
  function safeLevel(l) { return ["low", "medium", "high", "critical"].indexOf(l) >= 0 ? l : "low"; }

  async function loadRules() {
    if (state.rules) return state.rules;
    var res = await fetch("rules.json", { cache: "no-cache" });
    if (!res.ok) throw new Error("Could not load rules.json");
    state.rules = S.parseRules(await res.text());
    return state.rules;
  }

  function renderWarnings(list) {
    var box = $("warnings");
    box.textContent = "";
    list.forEach(function (w) { box.appendChild(el("div", "warn", w)); });
  }

  function kindFor(chainName) { return chainName === "solana" ? "solana" : "evm"; }

  /** The wallet to revoke with: the one the user picked, or the only one installed. */
  function walletFor(kind) {
    if (state.wallet && state.wallet.kind === kind) return state.wallet;
    var all = wallets.list(kind);
    return all.length === 1 ? all[0] : null;
  }

  function renderWalletPicker() {
    var box = $("wallet-list");
    var kind = kindFor($("chain").value);
    box.textContent = "";
    var all = wallets.list(kind);
    if (!all.length) {
      box.appendChild(el("p", null, "No " + (kind === "solana" ? "Solana" : "EVM") + " wallet detected. Install a wallet extension and reload, or paste an address to scan without one."));
      return;
    }
    all.forEach(function (w) {
      var b = el("button", null, null);
      b.type = "button";
      if (w.icon) { var img = document.createElement("img"); img.src = w.icon; img.alt = ""; img.width = 20; img.height = 20; b.appendChild(img); }
      b.appendChild(el("span", null, w.name));
      b.addEventListener("click", function () { chooseWallet(w); });
      box.appendChild(b);
    });
  }

  async function chooseWallet(w) {
    try {
      setStatus("Approve the connection in " + w.name + "…");
      var address = w.kind === "solana" ? await w.connect() : await wallets.connectEvm(w);
      state.wallet = w;
      $("address").value = address;
      $("wallet-picker").classList.add("hidden");
      setStatus("Connected " + w.name + " (read-only until you click Revoke).");
    } catch (e) {
      setStatus("Wallet connection cancelled" + (e && e.message ? ": " + e.message : "."));
    }
  }

  function renderResults(result, chain) {
    var box = $("results");
    box.textContent = "";
    if (!result.approvals.length) {
      box.appendChild(el("div", "card", "No active token approvals found."));
      return;
    }
    result.approvals.forEach(function (item) {
      var a = item.approval;
      var card = el("div", "card lvl-" + safeLevel(item.risk.level));
      var head = el("div", "row");
      head.appendChild(el("span", "badge " + safeLevel(item.risk.level), item.risk.level.toUpperCase() + " " + item.risk.score));
      head.appendChild(el("strong", null, item.explanation));
      card.appendChild(head);
      card.appendChild(el("p", "mono", "Token " + a.token));
      card.appendChild(el("p", "mono", "Spender " + a.spender));
      var row = el("div", "row");
      var link = el("a", "btn", "View spender");
      link.href = chain.explorer + (chain.name === "solana" ? "/account/" : "/address/") + a.spender;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      row.appendChild(link);
      var rev = el("button", "primary", "Revoke");
      rev.type = "button";
      rev.addEventListener("click", function () { revoke(rev, chain, a); });
      row.appendChild(rev);
      card.appendChild(row);
      box.appendChild(card);
    });
  }

  async function revoke(btn, chain, approval) {
    if (chain.name === "solana") return revokeSolana(btn, chain, approval);
    var w = walletFor("evm");
    if (!w) { setStatus("Connect a wallet first (use Connect wallet), or use the CLI."); return; }
    btn.disabled = true;
    try {
      setStatus("Confirm the revoke in " + w.name + "…");
      var hash = await S.sendRevoke(w.provider, chain, { owner: approval.owner, token: approval.token, spender: approval.spender });
      setStatus("Revoke submitted: " + hash);
    } catch (e) {
      setStatus("Revoke not sent: " + (e && e.message ? e.message : "cancelled"));
      btn.disabled = false;
    }
  }

  async function revokeSolana(btn, chain, approval) {
    var w = walletFor("solana");
    if (!w) { setStatus("Connect a Solana wallet first (use Connect wallet), or use the CLI."); return; }
    btn.disabled = true;
    try {
      setStatus("Confirm the revoke in " + w.name + "…");
      var reader = S.createRpc({ urls: chain.rpcs, minIntervalMs: S.SOLANA.minIntervalMs });
      var sig = await S.sendSolanaRevoke(w, reader, approval);
      setStatus("Revoke submitted: " + sig);
    } catch (e) {
      setStatus("Revoke not sent: " + (e && e.message ? e.message : "cancelled"));
      btn.disabled = false;
    }
  }

  async function scan(chainName, address) {
    if (state.scanning) return;
    state.scanning = true;
    $("go").disabled = true;
    $("results").textContent = "";
    renderWarnings([]);
    var bar = $("bar");
    try {
      var isSol = chainName === "solana";
      var chain = isSol ? { name: "solana", rpcs: S.SOLANA.rpcs, explorer: S.SOLANA.explorer } : S.getChain(chainName);
      if (!chain) throw new Error("Unknown chain");
      if (isSol) {
        if (!S.isSolanaAddress(address)) throw new Error("Not a valid Solana address");
      } else {
        address = S.normalizeAddress(address);
      }
      var rules = await loadRules();
      setStatus("Scanning " + chain.name + "…");
      bar.classList.remove("hidden");
      bar.value = 0;
      var reader = S.createRpc({ urls: chain.rpcs, expectedChainId: isSol ? undefined : chain.id, minIntervalMs: isSol ? S.SOLANA.minIntervalMs : undefined });
      var cache = (function () { try { return S.storageCache(window.localStorage); } catch (e) { return S.memoryCache(); } })();
      var blocklist = isSol ? null : await S.loadBlocklist({ fetchImpl: window.fetch.bind(window), urls: S.BLOCKLIST_URLS, cache: cache });
      var result = isSol
        ? await S.scanSolana({ reader: reader, rules: rules, owner: address })
        : await S.scanWallet({
            reader: reader, chain: chain, rules: rules, owner: address, cache: cache, blocklist: blocklist,
            fetchImpl: window.fetch.bind(window),
            onProgress: function (done, total) { if (total > 0) bar.value = Math.min(100, Math.round((done / total) * 100)); },
          });
      renderResults(result, chain);
      renderWarnings(result.warnings);
      setStatus(result.approvals.length + " active approval(s). Scanned to block " + result.scannedToBlock + ".");
      $("share").classList.remove("hidden");
      history.replaceState(null, "", S.buildHash(chain.name, address));
    } catch (e) {
      setStatus("Scan failed: " + (e && e.message ? e.message : "unknown error"));
    } finally {
      bar.classList.add("hidden");
      $("go").disabled = false;
      state.scanning = false;
    }
  }

  $("form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    scan($("chain").value, $("address").value.trim());
  });

  $("connect").addEventListener("click", function () {
    var picker = $("wallet-picker");
    renderWalletPicker();
    picker.classList.toggle("hidden");
  });
  $("wallet-close").addEventListener("click", function () { $("wallet-picker").classList.add("hidden"); });
  wallets.onChange(function () { if (!$("wallet-picker").classList.contains("hidden")) renderWalletPicker(); });
  $("chain").addEventListener("change", function () {
    if (state.wallet && state.wallet.kind !== kindFor($("chain").value)) state.wallet = null;
    if (!$("wallet-picker").classList.contains("hidden")) renderWalletPicker();
  });

  $("share").addEventListener("click", function () {
    try {
      navigator.clipboard.writeText(location.href).then(function () { setStatus("Share link copied."); });
    } catch (e) { setStatus("Copy the address bar URL to share."); }
  });

  var parsed = S.parseHash(location.hash);
  if (parsed) {
    $("chain").value = parsed.chain;
    $("address").value = parsed.address;
    scan(parsed.chain, parsed.address);
  }
})();
