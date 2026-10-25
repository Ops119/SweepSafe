(function () {
  "use strict";
  var S = window.SweepSafe;
  var $ = function (id) { return document.getElementById(id); };
  var state = { rules: null, wallet: null, account: null, scanning: false };

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

  function solanaProvider() {
    return (window.phantom && window.phantom.solana) || window.solana || null;
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
    if (!window.ethereum) { setStatus("No browser wallet found. Install one, or use the CLI."); return; }
    btn.disabled = true;
    try {
      setStatus("Confirm the revoke in your wallet…");
      var hash = await S.sendRevoke(window.ethereum, chain, { owner: approval.owner, token: approval.token, spender: approval.spender });
      setStatus("Revoke submitted: " + hash);
    } catch (e) {
      setStatus("Revoke not sent: " + (e && e.message ? e.message : "cancelled"));
      btn.disabled = false;
    }
  }

  async function revokeSolana(btn, chain, approval) {
    var provider = solanaProvider();
    if (!provider) { setStatus("No Solana wallet found. Install Phantom, or use the CLI."); return; }
    btn.disabled = true;
    try {
      setStatus("Confirm the revoke in your wallet…");
      var reader = S.createRpc({ urls: chain.rpcs, minIntervalMs: S.SOLANA.minIntervalMs });
      var sig = await S.sendSolanaRevoke(provider, reader, approval);
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

  $("connect").addEventListener("click", async function () {
    if ($("chain").value === "solana") {
      var sp = solanaProvider();
      if (!sp) { setStatus("No Solana wallet found. You can still scan any address."); return; }
      try {
        var r = await sp.connect();
        $("address").value = String((r && r.publicKey) || sp.publicKey || "");
        setStatus("Wallet connected (read-only until you click Revoke).");
      } catch (e) { setStatus("Wallet connection cancelled."); }
      return;
    }
    if (!window.ethereum) { setStatus("No browser wallet found. You can still scan any address."); return; }
    try {
      var accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
      if (accounts && accounts[0]) { $("address").value = accounts[0]; setStatus("Wallet connected (read-only until you click Revoke)."); }
    } catch (e) { setStatus("Wallet connection cancelled."); }
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
