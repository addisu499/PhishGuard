"""Shared helpers: Signal type, watchlist loading, domain utilities."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from functools import lru_cache
from urllib.parse import urlparse

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# Multi-part public suffixes we care about (small on purpose; no external deps).
MULTI_SUFFIXES = {
    "com.et", "gov.et", "org.et", "edu.et", "net.et", "sch.et",
    "co.uk", "org.uk", "ac.uk", "com.au", "co.za", "co.ke", "com.ng",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
    "qrco.de", "q-r.to", "qr.codes", "scanned.page",   # QR / redirect services
}

# Top-level domains often reported as heavily abused (cheap, little vetting).
# Weak signal only; verify/refresh against a current source such as Spamhaus' abused-TLD ranking.
RISKY_TLDS = {
    "top", "icu", "xyz", "digital", "lol", "pro", "site", "shop", "click", "live", "online",
    "cfd", "sbs", "cyou", "buzz", "rest", "work", "support", "monster", "bond", "vip", "cc",
    "tk", "ml", "ga", "cf", "gq", "link", "wang", "fit", "quest", "autos", "beauty", "mom",
}

# Free hosting / site-builder platforms whose subdomains anyone can create.
ABUSED_HOSTS = {
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "netlify.app", "vercel.app",
    "github.io", "blogspot.com", "weebly.com", "wixsite.com", "000webhostapp.com", "glitch.me",
    "herokuapp.com", "ngrok-free.app", "ngrok.io", "r2.dev", "webflow.io", "godaddysites.com",
    "myportfolio.com", "square.site", "mystrikingly.com", "framer.website", "carrd.co",
}


@dataclass
class Signal:
    name: str
    weight: int
    detail: str
    source: str  # "url" | "content" | "local"

    def to_dict(self):
        return asdict(self)


@lru_cache(maxsize=1)
def load_watchlist() -> dict:
    with open(os.path.join(DATA_DIR, "watchlist.json"), encoding="utf-8") as f:
        return json.load(f)


def get_host(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        host = ""
    return host.lower().rstrip(".")


def registered_domain(host: str) -> str:
    """Approximate eTLD+1 using a small suffix table."""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_label(host: str) -> str:
    """The brand-bearing label, e.g. 'paypal' from 'www.paypal.com'."""
    return registered_domain(host).split(".")[0]


def is_ip(host: str) -> bool:
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return True
    return ":" in host or bool(re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host))


def host_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def find_trusted_brand(host: str):
    """Return the watchlist entry whose official domains cover this host."""
    for entry in load_watchlist()["entries"]:
        if any(host_matches(host, d) for d in entry["domains"]):
            return entry
    return None


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
