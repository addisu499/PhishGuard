(async () => {
  const status = document.getElementById("status");
  const list = document.getElementById("signals");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const key = "verdict_" + tab.id;
  const res = (await chrome.storage.local.get(key))[key];
  status.textContent = "";
  if (!res) {
    status.textContent = "No result for this page. Is the engine running? (python server.py)";
    return;
  }
  const b = document.createElement("span");
  b.className = "badge " + res.verdict;
  b.textContent = res.verdict.toUpperCase() + " · " + res.score + "/100";
  status.appendChild(b);
  if (res.trusted_domain) status.appendChild(document.createTextNode("  Official domain: " + res.trusted_domain));
  if (!res.signals.length) {
    const li = document.createElement("li");
    li.textContent = "No warning signs found.";
    list.appendChild(li);
  }
  for (const s of res.signals) {
    const li = document.createElement("li");
    li.textContent = s.detail + " ";
    const w = document.createElement("span");
    w.className = "w";
    w.textContent = "(+" + s.weight + ", " + s.source + ")";
    li.appendChild(w);
    list.appendChild(li);
  }
})();
