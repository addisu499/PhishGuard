"""Weighted scorer + three-tier verdict (Safe / Suspicious / Dangerous)."""
from __future__ import annotations

from .common import Signal, find_trusted_brand, get_host
from .content_heuristics import analyze_content, parse_page
from .local_context import analyze_text
from .url_heuristics import analyze_url

SUSPICIOUS_AT = 20
DANGEROUS_AT = 60
DANGEROUS_FLOOR = 80   # brand mismatch + login form is high-confidence


def verdict_for(score: int) -> str:
    if score >= DANGEROUS_AT:
        return "dangerous"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "safe"


LOCAL_ONLY = {"homoglyph", "typosquat", "brand_wrong_suffix", "brand_in_domain", "brand_in_path",
              "brand_mismatch", "scam_phrasing"}


def analyze(url: str, html: str | None = None, use_local: bool = True) -> dict:
    """Analyze a URL (link scan) or a URL plus its page HTML (full page scan).

    use_local=False disables the local-context layer (watchlist and phrase signals,
    trusted-domain handling) so its contribution can be measured in the evaluation."""
    signals: list[Signal] = list(analyze_url(url))
    if html:
        page = parse_page(html)
        signals += analyze_content(url, page)
        signals += analyze_text(page.title + " " + page.text)

    host = get_host(url)
    if not use_local:
        signals = [s for s in signals if s.name not in LOCAL_ONLY]
    trusted = find_trusted_brand(host) if use_local else None
    if trusted is not None:
        # Official watchlist domain: only a form posting elsewhere stays suspicious.
        signals = [s for s in signals if s.name in ("external_form_action", "password_over_http")]
        if any(s.name == "external_form_action" and s.weight >= 25 for s in signals):
            signals.append(Signal("trusted_domain_posts_elsewhere", 15,
                                  "Official domain, but its login form submits to another site (possible compromise)", "content"))

    # Brand-independent combination: a password page whose address already looks risky.
    if trusted is None and any(s.name == "login_form" for s in signals):
        url_risk = sum(s.weight for s in signals if s.source == "url" and s.name != "no_https")
        if url_risk >= 10:
            signals.append(Signal("login_on_risky_url", 15,
                                  "Asks for a password on an address that already shows warning signs", "content"))
    score = min(100, sum(s.weight for s in signals))
    names = {s.name for s in signals}
    if "brand_mismatch" in names and "login_form" in names:
        score = max(score, DANGEROUS_FLOOR)

    return {
        "url": url,
        "score": score,
        "verdict": verdict_for(score),
        "mode": "page" if html else "link",
        "trusted_domain": trusted["brand"] if trusted else None,
        "signals": [s.to_dict() for s in sorted(signals, key=lambda s: -s.weight)],
    }
