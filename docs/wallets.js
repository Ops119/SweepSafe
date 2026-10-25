/* Browser wallet discovery. No dependencies, nothing is sent anywhere.
 *  - EVM: EIP-6963 multi-wallet discovery, plus a window.ethereum fallback.
 *  - Solana: Wallet Standard registration, plus legacy injected providers (Phantom, Solflare, Backpack).
 * Every wallet is normalized so the rest of the app never touches wallet-specific APIs.
 * Wallet names and icons come from third parties: names are sanitized, icons must be data: images,
 * and the page renders both with textContent / img.src only.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.SweepSafeWallets = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  function cleanName(value, fallback) {
    const text = Array.from(String(value == null ? "" : value))
      .filter((c) => { const n = c.codePointAt(0); return n >= 32 && n !== 127 && c !== "<" && c !== ">"; })
      .slice(0, 32).join("").trim();
    return text || fallback;
  }
  function cleanIcon(icon) {
    return typeof icon === "string" && icon.length < 200000 && /^data:image\/(png|jpeg|webp|gif|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(icon) ? icon : null;
  }

  /** @param win window-like object (EventTarget with Event/CustomEvent); @param S the SweepSafe core */
  function init(win, S) {
    const listeners = [];
    const evm = new Map();
    const solana = new Map();
    const changed = () => listeners.forEach((fn) => { try { fn(); } catch (e) { /* ignore */ } });

    // ---------------------------------------------------------------- EVM (EIP-6963)
    function addEvm(detail) {
      if (!detail || !detail.info || !detail.provider || typeof detail.provider.request !== "function") return;
      const key = String(detail.info.uuid || detail.info.rdns || detail.info.name || "");
      if (!key || evm.has(key)) return;
      evm.set(key, { id: "evm:" + key, kind: "evm", name: cleanName(detail.info.name, "Wallet"), icon: cleanIcon(detail.info.icon), provider: detail.provider });
      changed();
    }
    try {
      win.addEventListener("eip6963:announceProvider", (e) => addEvm(e && e.detail));
      win.dispatchEvent(new win.Event("eip6963:requestProvider"));
    } catch (e) { /* no event support */ }

    // ---------------------------------------------------------------- Solana (Wallet Standard)
    function standardWallet(w) {
      const f = w && w.features;
      if (!f || !f["standard:connect"] || !f["solana:signAndSendTransaction"]) return null;
      if (!Array.isArray(w.chains) || !w.chains.some((c) => String(c).startsWith("solana:"))) return null;
      const chain = w.chains.includes("solana:mainnet") ? "solana:mainnet" : null;
      if (!chain) return null; // a wallet that cannot do mainnet is useless here
      const entry = {
        id: "sol:" + cleanName(w.name, "wallet"), kind: "solana", name: cleanName(w.name, "Solana wallet"), icon: cleanIcon(w.icon),
        account: null,
        async connect() {
          if (entry.account) return entry.account.address;
          const res = await f["standard:connect"].connect();
          const accounts = (res && res.accounts && res.accounts.length ? res.accounts : w.accounts) || [];
          if (!accounts[0]) throw new Error("The wallet did not share an account.");
          entry.account = accounts[0];
          return String(entry.account.address);
        },
        async signAndSend(raw) {
          if (!entry.account) await entry.connect();
          const out = await f["solana:signAndSendTransaction"].signAndSendTransaction({ account: entry.account, chain, transaction: raw });
          const sig = out && out[0] && out[0].signature;
          if (!sig) throw new Error("The wallet did not return a signature.");
          return typeof sig === "string" ? sig : S.b58encode(sig);
        },
      };
      return entry;
    }
    const api = {
      register(...wallets) {
        for (const w of wallets) {
          const entry = standardWallet(w);
          if (entry && !solana.has(entry.id)) solana.set(entry.id, entry);
        }
        changed();
        return () => {};
      },
    };
    try {
      win.addEventListener("wallet-standard:register-wallet", (e) => { try { e.detail(api); } catch (err) { /* ignore */ } });
      win.dispatchEvent(new win.CustomEvent("wallet-standard:app-ready", { detail: api }));
    } catch (e) { /* no event support */ }

    // ---------------------------------------------------------------- legacy fallbacks
    function legacyEvm() {
      const eth = win.ethereum;
      if (!eth || typeof eth.request !== "function") return [];
      const known = Array.from(evm.values()).map((w) => w.provider);
      if (known.includes(eth)) return [];
      return [{ id: "evm:injected", kind: "evm", name: "Browser wallet", icon: null, provider: eth }];
    }
    function legacySolana() {
      const standardNames = Array.from(solana.values()).map((w) => w.name.toLowerCase());
      const candidates = [
        ["Phantom", win.phantom && win.phantom.solana],
        ["Solflare", win.solflare],
        ["Backpack", win.backpack],
        ["Browser Solana wallet", win.solana],
      ];
      const seen = new Set();
      const out = [];
      for (const [name, p] of candidates) {
        if (!p || typeof p.connect !== "function" || seen.has(p)) continue;
        seen.add(p);
        if (standardNames.includes(name.toLowerCase())) continue;
        const entry = {
          id: "sol:legacy:" + name, kind: "solana", name, icon: null,
          async connect() {
            const r = await p.connect();
            return String((r && r.publicKey) || p.publicKey || "");
          },
          async signAndSend(raw) {
            if (typeof p.request !== "function") throw new Error("This wallet cannot send pre-built transactions. Use the CLI instead.");
            const sent = await p.request({ method: "signAndSendTransaction", params: { message: S.b58encode(raw) } });
            const sig = sent && sent.signature ? sent.signature : sent;
            if (!sig) throw new Error("The wallet did not return a signature.");
            return String(sig);
          },
        };
        out.push(entry);
      }
      return out;
    }

    return {
      list(kind) {
        if (kind === "solana") return Array.from(solana.values()).concat(legacySolana());
        return Array.from(evm.values()).concat(legacyEvm());
      },
      onChange(fn) { listeners.push(fn); },
      /** EVM: ask the chosen wallet for its account (prompts the user). */
      async connectEvm(entry) {
        const accounts = await entry.provider.request({ method: "eth_requestAccounts" });
        const first = String((accounts && accounts[0]) || "").toLowerCase();
        if (!S.isAddress(first)) throw new Error("The wallet did not share an account.");
        return first;
      },
    };
  }

  return { init, cleanName, cleanIcon };
});
