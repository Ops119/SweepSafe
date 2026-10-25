(function () {
  "use strict";
  var S = window.SweepSafe;
  var root = document.getElementById("demo");
  if (!root || !S) return;
  var $ = function (id) { return document.getElementById(id); };
  var out = $("demo-out"), badge = $("demo-badge");
  var rules = null;

  // Fixed sample addresses, not real wallets.
  var TOKEN = "0x" + "a0".repeat(20);
  var SPENDER = "0x" + "5e".repeat(20);

  function update() {
    if (!rules) return;
    var spender = $("demo-spender").value;
    var unlimited = $("demo-allowance").value === "unlimited";
    var allowance = unlimited ? S.MAX_UINT256 : 500000000n;
    var risk = S.evaluateRisk(rules, {
      allowance: allowance,
      spender_is_contract: spender !== "wallet" && spender !== "scam",
      verification: spender === "verified" ? "verified" : spender === "unverified" ? "unverified" : "unknown",
      blocklisted: spender === "scam",
      age_days: Number($("demo-age").value),
    });
    var approval = { token: TOKEN, spender: SPENDER, allowance: allowance, tokenSymbol: "USDC", tokenDecimals: 6 };
    out.textContent = S.explainApproval(rules, approval, risk);
    badge.textContent = risk.level.toUpperCase() + " " + risk.score;
    badge.className = "badge " + (["low", "medium", "high", "critical"].indexOf(risk.level) >= 0 ? risk.level : "low");
  }

  ["demo-allowance", "demo-spender", "demo-age"].forEach(function (id) { $(id).addEventListener("change", update); });
  fetch("rules.json", { cache: "no-cache" })
    .then(function (r) { if (!r.ok) throw new Error("rules"); return r.text(); })
    .then(function (text) { rules = S.parseRules(text); update(); })
    .catch(function () { out.textContent = "Could not load the rules for the demo."; });
})();
