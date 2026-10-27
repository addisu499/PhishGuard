"""Generate a coverage test set of look-alike URLs for the *local* watchlist brands.

IMPORTANT (state this in the report): these URLs are generated from the same kinds of
tricks the detector looks for, so this is a design-coverage test of the local-context
layer, not an independent estimate of real-world accuracy. Replace or extend it with real
reported local phishing URLs if you can collect them.

Usage:  python eval/make_local_set.py   ->  eval/local_phish.txt, eval/local_benign.txt
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine.common import domain_label, registered_domain

HERE = os.path.dirname(os.path.abspath(__file__))
wl = json.load(open(os.path.join(HERE, "..", "engine", "data", "watchlist.json"), encoding="utf-8"))
HOMO = {"o": "0", "l": "1", "i": "1", "e": "3", "s": "5"}


def typos(label):
    out = set()
    if len(label) >= 5:
        out.add(label[:2] + label[3:])                       # drop a letter
        out.add(label[:2] + label[3] + label[2] + label[4:])  # swap two letters
    out.add(label[:1] + label[1] * 2 + label[2:])             # double a letter
    return {t for t in out if t != label}


def homoglyphs(label):
    out = set()
    for i, c in enumerate(label):
        if c in HOMO:
            out.add(label[:i] + HOMO[c] + label[i + 1:])
    if "m" in label:
        out.add(label.replace("m", "rn", 1))
    return {h for h in out if h != label}


phish, benign = [], []
for e in wl["entries"]:
    if not e.get("local"):
        continue
    for official in e["domains"]:
        reg = registered_domain(official)
        label = domain_label(official)
        suffix = reg[len(label):]                              # e.g. ".com.et"
        benign.append(f"https://{official}/")
        for t in sorted(typos(label))[:3]:
            phish.append(f"https://{t}{suffix}/login")
        for h in sorted(homoglyphs(label))[:2]:
            phish.append(f"https://{h}{suffix}/signin")
        for s in (".com", ".net", ".org"):
            if s != suffix:
                phish.append(f"https://{label}{s}/")
        phish += [f"https://{label}-login-secure.com/verify",
                  f"https://secure-{label}.xyz/account/update",
                  f"https://{label}-online.top/login",
                  f"https://{official}.verify-account.site/login"]
    for kw in e["keywords"]:
        if " " not in kw and len(kw) >= 4:
            phish.append(f"https://{kw}-bonus-claim.click/")
            phish.append(f"https://my-{kw}.cfd/payment")

phish = sorted(set(phish)); benign = sorted(set(benign))
open(os.path.join(HERE, "local_phish.txt"), "w").write("# generated look-alikes of local watchlist brands\n" + "\n".join(phish) + "\n")
open(os.path.join(HERE, "local_benign.txt"), "w").write("# official local sites\n" + "\n".join(benign) + "\n")
print(len(phish), "phishing-style URLs,", len(benign), "official URLs")
