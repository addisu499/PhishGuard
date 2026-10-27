// MV3 service worker: may be killed at any time, so verdicts live in chrome.storage, not memory.
const API = "http://127.0.0.1:8765/analyze";
const COLORS = { safe: "#2e7d32", suspicious: "#f9a825", dangerous: "#c62828" };
const BADGE = { safe: "", suspicious: "?", dangerous: "!!" };
const ICON_SET = { safe: "icon", suspicious: "warn", dangerous: "danger" };
const iconPaths = (verdict) =>
  Object.fromEntries([16, 32, 48, 128].map((n) => [n, `icons/${ICON_SET[verdict]}-${n}.png`]));

async function analyze(payload) {
  const r = await fetch(API, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error("engine error " + r.status);
  return r.json();
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "page" && sender.tab) {
    const tabId = sender.tab.id;
    analyze({ url: msg.url, html: msg.html })
      .then(async (res) => {
        await chrome.storage.local.set({ ["verdict_" + tabId]: res });
        await chrome.action.setIcon({ tabId, path: iconPaths(res.verdict) });
        await chrome.action.setBadgeText({ tabId, text: BADGE[res.verdict] });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS[res.verdict] });
        sendResponse(res);
      })
      .catch(async () => {
        await chrome.action.setBadgeText({ tabId, text: "off" });
        sendResponse(null); // engine not running
      });
    return true; // async response
  }
  if (msg.type === "link") {
    analyze({ url: msg.url }).then(sendResponse).catch(() => sendResponse(null));
    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.local.remove("verdict_" + tabId));
