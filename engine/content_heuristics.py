"""Layer 2: page-content heuristics, computed from the page's HTML (stdlib parser)."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from .common import Signal, get_host, host_matches, load_watchlist, registered_domain

OFFSCREEN = re.compile(r"(left|top)\s*:\s*-\d{3,}|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(\.0+)?\b", re.I)
SENSITIVE_TYPES = {"password", "email", "tel", "text"}
MAX_TEXT = 4000
URL_LIKE_TEXT = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", re.I)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.forms: list[dict] = []
        self._form: dict | None = None
        self.img_hints: list[str] = []      # alt text + logo-ish filenames
        self.meta_site_name = ""
        self.text_parts: list[str] = []
        self._skip = 0
        self._text_len = 0
        self.anchors: list[tuple[str, str]] = []   # (href, visible text)
        self._a_href: str | None = None
        self._a_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "a":
            self._a_href, self._a_text = a.get("href", ""), []
        if tag == "title":
            self._in_title = True
        elif tag in ("script", "style"):
            self._skip += 1
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "inputs": []}
            self.forms.append(self._form)
        elif tag == "input":
            item = {"type": a.get("type", "text").lower(), "style": a.get("style", ""),
                    "hidden_attr": "hidden" in a, "name": a.get("name", "")}
            if self._form is not None:
                self._form["inputs"].append(item)
            else:  # login boxes built without <form>
                self.forms.append({"action": "", "inputs": [item], "implicit": True})
        elif tag == "img":
            hint = " ".join([a.get("alt", ""), a.get("src", "").rsplit("/", 1)[-1]])
            if re.search(r"logo|brand", hint, re.I) or a.get("alt"):
                self.img_hints.append(hint.lower())
        elif tag == "meta" and a.get("property", "").lower() == "og:site_name":
            self.meta_site_name = a.get("content", "")

    def handle_endtag(self, tag):
        if tag == "a" and self._a_href is not None:
            self.anchors.append((self._a_href, " ".join(self._a_text).strip()))
            self._a_href = None
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._a_href is not None:
            self._a_text.append(data.strip())
        if self._in_title:
            self.title += data
        elif not self._skip and self._text_len < MAX_TEXT:
            chunk = data.strip()
            if chunk:
                self.text_parts.append(chunk)
                self._text_len += len(chunk)

    @property
    def text(self) -> str:
        return " ".join(self.text_parts)


def parse_page(html: str) -> PageParser:
    p = PageParser()
    try:
        p.feed(html or "")
    except Exception:  # malformed HTML must never crash the engine
        pass
    return p


def analyze_content(url: str, page: PageParser) -> list[Signal]:
    signals: list[Signal] = []
    host = get_host(url)
    page_reg = registered_domain(host)
    scheme = urlparse(url).scheme

    has_password = any(i["type"] == "password" for f in page.forms for i in f["inputs"])
    if has_password and scheme == "http":
        signals.append(Signal("password_over_http", 20, "Password field on a page that is not HTTPS", "content"))

    # Off-screen / hidden *visible-type* fields (hidden CSRF tokens are normal and ignored).
    sneaky = [i for f in page.forms for i in f["inputs"]
              if i["type"] in SENSITIVE_TYPES and (OFFSCREEN.search(i["style"]) or i["hidden_attr"])]
    if sneaky:
        signals.append(Signal("offscreen_fields", 15,
                              f"{len(sneaky)} text/credential field(s) hidden or placed off-screen", "content"))

    # Form posts to a different registered domain.
    for f in page.forms:
        action = (f.get("action") or "").strip()
        if not action or action.startswith(("#", "javascript:")):
            continue
        target = get_host(urljoin(url, action))
        if target and registered_domain(target) != page_reg:
            takes_creds = any(i["type"] in ("password", "email", "tel") for i in f["inputs"])
            w = 25 if takes_creds else 8
            signals.append(Signal("external_form_action", w,
                                  f"Form submits to a different domain ({target})", "content"))
            break

    # Brand / domain mismatch: brand shown in title / logo alt-text / site name,
    # but the page is not hosted on that brand's domains.
    shown = " ".join([page.title, page.meta_site_name] + page.img_hints).lower()
    for entry in load_watchlist()["entries"]:
        if any(host_matches(host, d) for d in entry["domains"]):
            continue
        hit = next((k for k in entry["keywords"] if _word_in(k, shown)), None)
        if hit:
            w = 40 if has_password else 18
            signals.append(Signal("brand_mismatch", w,
                                  f"Page presents itself as {entry['brand']} (matched '{hit}') but is hosted on {page_reg}",
                                  "content"))
            break

    # Link text that shows one address while the link goes to another (classic lure).
    mism = []
    for href, text in page.anchors:
        if not href.lower().startswith(("http://", "https://")) or len(text) > 80 or not URL_LIKE_TEXT.match(text):
            continue
        shown = get_host(text if "://" in text else "http://" + text)
        real = get_host(href)
        if shown and real and registered_domain(shown) != registered_domain(real):
            mism.append((text, real))
    if mism:
        signals.append(Signal("link_text_mismatch", 15 if len(mism) < 3 else 20,
                              f"{len(mism)} link(s) display one address but go to another (e.g. shows {mism[0][0]}, goes to {mism[0][1]})",
                              "content"))

    # A local institution named repeatedly on a page that asks for a password, but hosted elsewhere
    # (covers clones whose title and logo text do not name the brand).
    if has_password and not any(x.name == "brand_mismatch" for x in signals):
        body = page.text.lower()
        for entry in load_watchlist()["entries"]:
            if not entry.get("local") or any(host_matches(host, d) for d in entry["domains"]):
                continue
            n = sum(len(re.findall(r"(?<![a-z0-9])" + re.escape(k.lower()) + r"(?![a-z0-9])", body))
                    for k in entry["keywords"] if len(k) >= 3)
            if n >= 2:
                signals.append(Signal("brand_mention_with_login", 25,
                                      f"Page names {entry['brand']} {n} times and asks for a password, but is hosted on {page_reg}",
                                      "content"))
                break

    if has_password:
        signals.append(Signal("login_form", 5, "Page asks for a password", "content"))
    return signals


def _word_in(keyword: str, text: str) -> bool:
    return re.search(r"(?<![a-z0-9])" + re.escape(keyword.lower()) + r"(?![a-z0-9])", text) is not None
