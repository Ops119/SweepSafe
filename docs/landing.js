(function () {
  "use strict";
  var btn = document.getElementById("copy");
  var cmd = document.getElementById("cmd");
  if (!btn || !cmd) return;
  btn.addEventListener("click", function () {
    var done = function (ok) {
      btn.textContent = ok ? "Copied" : "Press Ctrl+C";
      setTimeout(function () { btn.textContent = "Copy"; }, 1500);
    };
    try {
      navigator.clipboard.writeText(cmd.textContent).then(function () { done(true); }, function () { done(false); });
    } catch (e) { done(false); }
  });
})();
