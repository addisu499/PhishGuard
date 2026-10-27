"""Layer 3: local-context layer — scam phrasing in Amharic and English.

(Watchlist-based impersonation checks live in url_heuristics / content_heuristics
because they need the URL and DOM; this module covers the language side.)

Phrases are grouped by kind. 'Pressure' kinds (threat, urgency, prize, bonus) are what scams
use; wording about passwords or verification is common on legitimate pages, so it only adds
weight when a pressure phrase is also present.
"""
from __future__ import annotations

from .common import Signal, load_watchlist

PRESSURE = {"threat", "urgency", "prize", "bonus"}


def analyze_text(text: str) -> list[Signal]:
    if not text:
        return []
    wl = load_watchlist()
    low = text.lower()
    hits = []
    for p in wl["amharic_phrases"]:
        if p["text"] in text:
            hits.append(("am", p))
    for p in wl["english_phrases"]:
        if p["text"] in low:
            hits.append(("en", p))
    pressure = [(l, p) for l, p in hits if p["kind"] in PRESSURE]
    if not pressure:
        return []
    context = [h for h in hits if h[1]["kind"] not in PRESSURE]
    weight = (10 if len(pressure) == 1 else 20) + (5 if context else 0)
    langs = {l for l, _ in pressure}
    label = "Amharic" if langs == {"am"} else "English" if langs == {"en"} else "Amharic/English"
    sample = ", ".join(p.get("meaning") or p["text"] for _, p in pressure[:3])
    return [Signal("scam_phrasing", weight,
                   f"{label} scam-style wording ({len(pressure)} pressure phrase(s)): {sample}", "local")]
