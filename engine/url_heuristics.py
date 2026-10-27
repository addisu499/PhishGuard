"""Layer 1: URL / domain heuristics (also used for pre-click link scanning)."""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse

from .common import (
    ABUSED_HOSTS, RISKY_TLDS, SHORTENERS, Signal, domain_label, find_trusted_brand, get_host, is_ip,
    levenshtein, load_watchlist, registered_domain,
)

# Common look-alike substitutions (ASCII digits + a few Cyrillic letters).
CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "5": "s", "$": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i",
}
SEQUENCES = [("rn", "m"), ("vv", "w")]
SUSPICIOUS_WORDS = ["login", "signin", "verify", "secure", "account", "update",
                    "confirm", "banking", "wallet", "suspend", "unlock", "billing",
                    "payment", "password", "captcha", "invoice"]


def decode_host(host: str) -> str:
    """Unicode form of an internationalized host (xn-- labels); falls back to the input."""
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        return host


def uhost_for_hyphens(host: str) -> str:
    return decode_host(host) if "xn--" in host else host


def mixed_script(text: str) -> bool:
    """True if any single label mixes Latin letters with letters of another script."""
    for label in text.split("."):
        scripts = {unicodedata.name(c, "").split(" ")[0] for c in label if c.isalpha()}
        if "LATIN" in scripts and len(scripts) > 1:
            return True
    return False


def normalize_homoglyphs(label: str) -> str:
    out = "".join(CONFUSABLES.get(c, c) for c in label.lower())
    for a, b in SEQUENCES:
        out = out.replace(a, b)
    return out


def analyze_url(url: str) -> list[Signal]:
    signals: list[Signal] = []
    try:
        parsed = urlparse(url)
    except ValueError:
        return [Signal("malformed_url", 20, "URL could not be parsed", "url")]
    host = get_host(url)
    if not host:
        return signals

    trusted = find_trusted_brand(host)
    reg = registered_domain(host)

    if parsed.scheme == "http":
        signals.append(Signal("no_https", 10, "Page is not served over HTTPS", "url"))
    if is_ip(host):
        signals.append(Signal("ip_host", 25, f"Raw IP address used instead of a domain ({host})", "url"))
    if "@" in (parsed.netloc or ""):
        signals.append(Signal("at_in_url", 15, "'@' in the address can hide the real destination", "url"))
    if reg in SHORTENERS:
        signals.append(Signal("url_shortener", 10, f"Link goes through a shortener ({reg}); real destination hidden", "url"))
    if host.count(".") >= 4:
        signals.append(Signal("many_subdomains", 10, f"{host.count('.')} dots in hostname", "url"))
    if uhost_for_hyphens(host).count("-") >= 3:
        signals.append(Signal("many_hyphens", 8, f"{uhost_for_hyphens(host).count('-')} hyphens in hostname", "url"))
    digits = sum(c.isdigit() for c in host)
    if host and digits / len(host) > 0.3 and not is_ip(host):
        signals.append(Signal("digit_heavy", 6, "Hostname is unusually digit-heavy", "url"))
    uhost = decode_host(host)
    if mixed_script(uhost):
        signals.append(Signal("mixed_script", 15, "Domain mixes Latin letters with another alphabet; may imitate another site", "url"))
    if len(url) > 120:
        signals.append(Signal("long_url", 5, f"Very long URL ({len(url)} chars)", "url"))

    if trusted is None:
        signals.extend(_lexical(host, reg))
        words = [w for w in SUSPICIOUS_WORDS if w in host]
        if words:
            signals.append(Signal("suspicious_words_host", min(5 * len(words), 12),
                                  "Hostname contains: " + ", ".join(words), "url"))
        path_words = [w for w in SUSPICIOUS_WORDS if w in (parsed.path or "").lower()]
        if path_words:
            signals.append(Signal("suspicious_words_path", 4, "Path contains: " + ", ".join(path_words), "url"))
        signals.extend(_brand_lookalike(uhost, parsed.path or ""))
    return signals


def _brand_lookalike(host: str, path: str) -> list[Signal]:
    """Typosquat / homoglyph / brand-in-domain checks against the watchlist.
    Only the single strongest brand signal is reported."""
    label = domain_label(host)
    norm = normalize_homoglyphs(label)
    labels = host.split(".")
    tokens = set(re.split(r"[.\-_]", ".".join(labels[:-1]))) if len(labels) > 1 else set()
    tld = labels[-1]
    best = None  # (weight, Signal)

    def consider(sig: Signal):
        nonlocal best
        if best is None or sig.weight > best.weight:
            best = sig

    for entry in load_watchlist()["entries"]:
        for official in entry["domains"]:
            off_label = domain_label(official)
            if len(off_label) < 3:
                continue
            if label == off_label:
                if not entry.get("local") and len(tld) == 2 and tld.isalpha():
                    consider(Signal("brand_other_cctld", 8,
                                    f"Uses '{off_label}' on a country domain (.{tld}); official site is {official}", "url"))
                else:
                    consider(Signal("brand_wrong_suffix", 35,
                                    f"Uses '{off_label}' but is not the official domain ({official})", "url"))
            elif norm == normalize_homoglyphs(off_label):
                consider(Signal("homoglyph", 60,
                                f"Looks like {entry['brand']} ({official}) using look-alike characters", "url"))
            else:
                d = levenshtein(norm, normalize_homoglyphs(off_label))
                if d <= (1 if len(off_label) < 8 else 2):
                    consider(Signal("typosquat", 45,
                                    f"Within {d} edit(s) of {entry['brand']} ({official})", "url"))
        kws = list(entry["keywords"])
        if entry.get("local"):  # a local brand's own domain label is distinctive (awashbank, dashenbanksc)
            kws += [domain_label(d) for d in entry["domains"] if len(domain_label(d)) >= 4]
        for kw in kws:
            if " " in kw or len(kw) < 3:
                continue
            if "-" in kw:  # hyphenated brand such as m-pesa: match as a whole word in the host
                hit = re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", ".".join(labels[:-1]))
            else:
                hit = kw in tokens
            if hit and kw != label:
                consider(Signal("brand_in_domain", 30,
                                f"Hostname mentions '{kw}' ({entry['brand']}) but is not an official domain", "url"))
            elif len(kw) >= 4 and "-" not in kw and kw in path.lower():
                consider(Signal("brand_in_path", 12,
                                f"Path mentions '{kw}' ({entry['brand']}) on an unrelated domain", "url"))
    return [best] if best else []


def _lexical(host: str, reg: str) -> list[Signal]:
    """Generic, brand-independent URL features (cover phishing for brands not on the watchlist)."""
    out: list[Signal] = []
    if is_ip(host):
        return out
    tld = host.rsplit(".", 1)[-1]
    label = domain_label(host)
    if tld in RISKY_TLDS:
        out.append(Signal("risky_tld", 10, f"Domain ends in .{tld}, a TLD frequently used for abuse", "url"))
    if host != reg and reg in ABUSED_HOSTS:
        out.append(Signal("free_hosting_subdomain", 15,
                          f"Hosted on a free subdomain of {reg}, which anyone can create", "url"))
    if re.search(r"\d{4,}", host):
        out.append(Signal("long_digit_run", 8, "Hostname contains a long run of digits", "url"))
    if "xn--" in host:      # encoded form of a non-Latin name always looks random; do not judge it
        return out
    letters = [c for c in label if c.isalpha()]
    vowels = sum(c in "aeiou" for c in letters)
    if (len(letters) >= 10 and vowels <= 1) or re.search(r"[bcdfghjklmnpqrstvwxz]{6,}", label):
        out.append(Signal("gibberish_domain", 10, f"Domain name '{label}' looks randomly generated", "url"))
    return out
