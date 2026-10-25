(function () {
  "use strict";
  // Donations go straight to this Solana address as USDC. SweepSafe never sees or holds funds.
  var ADDRESS = "75DDnCQt4HPP5bF55oSBvSrwuCSLcC7U2w9tc3kMmyrA";
  var USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
  var MIN = 1;
  var MAX = 10000; // USDC; always below GBP 10,000 so the cap holds whatever the exchange rate

  var root = document.getElementById("donate");
  if (!root) return;
  var amount = root.querySelector("[data-amount]");
  var link = root.querySelector("[data-pay]");
  var copy = root.querySelector("[data-copy]");
  var note = root.querySelector("[data-note]");
  root.querySelector("[data-address]").textContent = ADDRESS;

  function parse(text) {
    if (!/^\d{1,5}(\.\d{1,2})?$/.test(String(text).trim())) return null;
    var n = Number(text);
    return n >= MIN && n <= MAX ? n : null;
  }
  function refresh() {
    var n = parse(amount.value);
    if (n === null) {
      link.removeAttribute("href");
      link.setAttribute("aria-disabled", "true");
      note.textContent = "Enter an amount from " + MIN + " to " + MAX.toLocaleString("en-GB") + " USDC.";
      return;
    }
    var uri = "solana:" + ADDRESS + "?amount=" + n + "&spl-token=" + USDC_MINT +
      "&label=" + encodeURIComponent("SweepSafe") + "&message=" + encodeURIComponent("Thanks for supporting SweepSafe");
    link.setAttribute("href", uri);
    link.removeAttribute("aria-disabled");
    note.textContent = "Opens your Solana wallet to send " + n + " USDC. You confirm it there.";
  }
  amount.addEventListener("input", refresh);
  root.querySelectorAll("[data-preset]").forEach(function (b) {
    b.addEventListener("click", function () { amount.value = b.getAttribute("data-preset"); refresh(); });
  });
  copy.addEventListener("click", function () {
    var done = function (ok) {
      copy.textContent = ok ? "Copied" : "Select the address";
      setTimeout(function () { copy.textContent = "Copy address"; }, 1500);
    };
    try { navigator.clipboard.writeText(ADDRESS).then(function () { done(true); }, function () { done(false); }); }
    catch (e) { done(false); }
  });
  refresh();
})();
