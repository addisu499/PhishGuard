// Page scan + pre-click link scan. All untrusted strings go through textContent (never innerHTML).
(() => {
  if (window.top !== window) return; // top frame only

  const COLORS = { safe: "#2e7d32", suspicious: "#f9a825", dangerous: "#c62828" };

  function ask(msg) {
    return new Promise((resolve) => {
      try { chrome.runtime.sendMessage(msg, (res) => resolve(chrome.runtime.lastError ? null : res)); }
      catch { resolve(null); }
    });
  }

  function el(tag, styles, text) {
    const e = document.createElement(tag);
    Object.assign(e.style, styles || {});
    if (text) e.textContent = text;
    return e;
  }

  function reasons(res, max) {
    return res.signals.slice(0, max).map((s) => "• " + s.detail);
  }

  // ---- Full-page verdicts ----
  function showBanner(res) {
    const bar = el("div", {
      position: "fixed", top: "0", left: "0", right: "0", zIndex: "2147483647",
      background: COLORS.suspicious, color: "#222", font: "14px system-ui, sans-serif",
      padding: "8px 12px", display: "flex", gap: "12px", alignItems: "center",
    });
    bar.appendChild(el("strong", null, "PhishGuard: this page looks suspicious. "));
    bar.appendChild(el("span", { flex: "1" }, res.signals[0] ? res.signals[0].detail : ""));
    const x = el("button", { cursor: "pointer" }, "Dismiss");
    x.onclick = () => bar.remove();
    bar.appendChild(x);
    document.documentElement.appendChild(bar);
  }

  function showInterstitial(res) {
    const wall = el("div", {
      position: "fixed", inset: "0", zIndex: "2147483647", background: COLORS.dangerous,
      color: "#fff", font: "16px system-ui, sans-serif", display: "flex",
      alignItems: "center", justifyContent: "center", padding: "24px",
    });
    const box = el("div", { maxWidth: "620px" });
    box.appendChild(el("h1", { margin: "0 0 12px" }, "Warning: likely phishing page"));
    box.appendChild(el("p", null, "PhishGuard scored this page " + res.score + "/100. Do not enter passwords or payment details here."));
    reasons(res, 5).forEach((r) => box.appendChild(el("div", { margin: "4px 0" }, r)));
    const row = el("div", { marginTop: "20px", display: "flex", gap: "12px" });
    const back = el("button", { padding: "10px 16px", cursor: "pointer", fontWeight: "bold" }, "Take me to safety");
    back.onclick = () => { history.length > 1 ? history.back() : (location.href = "about:blank"); };
    const go = el("button", { padding: "10px 16px", cursor: "pointer" }, "I understand the risk, continue");
    go.onclick = () => wall.remove();
    row.append(back, go);
    box.appendChild(row);
    wall.appendChild(box);
    document.documentElement.appendChild(wall);
  }

  async function scanPage() {
    const html = document.documentElement.outerHTML.slice(0, 300000);
    const res = await ask({ type: "page", url: location.href, html });
    if (!res) return;
    if (res.verdict === "dangerous") showInterstitial(res);
    else if (res.verdict === "suspicious") showBanner(res);
  }

  // ---- Pre-click link scanning (hover) ----
  const cache = new Map();
  let tip = null, timer = null;

  function hideTip() { clearTimeout(timer); if (tip) { tip.remove(); tip = null; } }

  function showTip(a, res) {
    hideTip();
    if (!res || res.verdict === "safe") return;
    tip = el("div", {
      position: "fixed", zIndex: "2147483647", maxWidth: "340px", background: "#fff",
      color: "#111", border: "2px solid " + COLORS[res.verdict], borderRadius: "6px",
      padding: "8px 10px", font: "12px system-ui, sans-serif", boxShadow: "0 2px 8px rgba(0,0,0,.3)",
    });
    tip.appendChild(el("strong", { color: COLORS[res.verdict] },
      (res.verdict === "dangerous" ? "Dangerous link" : "Suspicious link") + " (" + res.score + "/100)"));
    reasons(res, 3).forEach((r) => tip.appendChild(el("div", null, r)));
    const rect = a.getBoundingClientRect();
    tip.style.left = Math.max(4, Math.min(rect.left, innerWidth - 350)) + "px";
    tip.style.top = Math.min(rect.bottom + 6, innerHeight - 80) + "px";
    document.documentElement.appendChild(tip);
  }

  document.addEventListener("mouseover", (e) => {
    const a = e.target.closest && e.target.closest("a[href]");
    if (!a || !/^https?:/i.test(a.href)) return;
    if (new URL(a.href).origin === location.origin) return; // same-site links skipped
    clearTimeout(timer);
    timer = setTimeout(async () => {
      let res = cache.get(a.href);
      if (res === undefined) { res = await ask({ type: "link", url: a.href }); cache.set(a.href, res); }
      showTip(a, res);
    }, 300);
  }, true);
  document.addEventListener("mouseout", hideTip, true);
  document.addEventListener("scroll", hideTip, true);

  scanPage();
})();
