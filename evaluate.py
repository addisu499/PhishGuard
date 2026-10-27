"""Formal evaluation: detection rate and false-positive rate.

Usage:
  python evaluate.py --phish eval/phish_sample.txt --benign eval/benign_sample.txt
  python evaluate.py --phishtank-csv verified_online.csv --tranco-csv top-1m.csv --n 500 --seed 1

Files are one URL (or domain, for Tranco) per line, or CSVs. URL-only mode scores
what a link scan sees; use --pages DIR to also score saved HTML clones
(DIR/<name>.html + DIR/<name>.url holding the URL).
Record the date/time of the PhishTank pull in your report: URLs go offline fast.
"""
import argparse, csv, datetime, glob, os, random
from engine import analyze


def read_lines(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def read_phishtank(path, n, seed):
    with open(path, encoding="utf-8", newline="") as f:
        urls = [r["url"] for r in csv.DictReader(f) if r.get("url")]
    random.Random(seed).shuffle(urls)
    return urls[:n]


def read_tranco(path, n, seed):
    with open(path, encoding="utf-8", newline="") as f:
        doms = [r[1] for r in csv.reader(f) if len(r) > 1]
    random.Random(seed).shuffle(doms)
    return ["https://" + d + "/" for d in doms[:n]]


def run(urls, flag_at, use_local=True):
    flagged, missed = [], []
    for u in urls:
        r = analyze(u, use_local=use_local)
        (flagged if r["verdict"] in flag_at else missed).append(r)
    return flagged, missed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish"); ap.add_argument("--benign")
    ap.add_argument("--phishtank-csv"); ap.add_argument("--tranco-csv")
    ap.add_argument("--extra-benign", help="file of local institutional URLs to add to the benign set")
    ap.add_argument("--n", type=int, default=500); ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--flag-at", choices=["suspicious", "dangerous"], default="suspicious",
                    help="lowest verdict that counts as 'flagged'")
    ap.add_argument("--sweep", action="store_true", help="print detection rate / false-positive rate for a range of score thresholds")
    ap.add_argument("--no-local", action="store_true", help="disable the local-context layer (for the ablation row)")
    ap.add_argument("--show", type=int, default=10, help="how many misses/false positives to list")
    a = ap.parse_args()

    phish = read_phishtank(a.phishtank_csv, a.n, a.seed) if a.phishtank_csv else read_lines(a.phish)
    benign = read_tranco(a.tranco_csv, a.n, a.seed) if a.tranco_csv else read_lines(a.benign)
    if a.extra_benign:
        benign += read_lines(a.extra_benign)
    flag_at = {"suspicious", "dangerous"} if a.flag_at == "suspicious" else {"dangerous"}

    tp, fn = run(phish, flag_at, not a.no_local)
    fp, tn = run(benign, flag_at, not a.no_local)
    dr = len(tp) / max(1, len(phish)); fpr = len(fp) / max(1, len(benign))
    prec = len(tp) / max(1, len(tp) + len(fp))

    print(f"Local-context layer: {'OFF' if a.no_local else 'ON'}")
    print(f"Run at {datetime.datetime.now().isoformat(timespec='seconds')} | flagged = verdict >= {a.flag_at}")
    print(f"Phishing samples: {len(phish)} | Benign samples: {len(benign)}")
    print(f"TP={len(tp)} FN={len(fn)} FP={len(fp)} TN={len(tn)}")
    print(f"Detection rate      : {dr:.1%}")
    print(f"False-positive rate : {fpr:.1%}")
    print(f"Precision           : {prec:.1%}")
    if a.sweep:
        ps = [analyze(u, use_local=not a.no_local)["score"] for u in phish]
        bs = [analyze(u, use_local=not a.no_local)["score"] for u in benign]
        print("\nThreshold sweep (flag when score >= T). Pick T by the trade-off, not by one sample.")
        print("  T    detection   false-positive")
        for t in (10, 15, 20, 25, 30, 40, 50, 60):
            d = sum(x >= t for x in ps) / max(1, len(ps)); f = sum(x >= t for x in bs) / max(1, len(bs))
            print(f"  {t:<4} {d:>8.1%}   {f:>10.1%}")
    print("\nMissed phishing (for the 'missed detection' walkthrough):")
    for r in fn[:a.show]: print("  ", r["score"], r["url"])
    print("\nFalse positives (for the 'false positive' walkthrough):")
    for r in fp[:a.show]: print("  ", r["score"], r["url"], [s["name"] for s in r["signals"]])


if __name__ == "__main__":
    main()
