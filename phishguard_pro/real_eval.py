"""
Measure the WHOLE PhishGuard system (rules + ML) on real URL lists.

    python real_eval.py --phish fresh_phishing.txt --legit real_legit_urls.txt top_domains_sample.txt

  Detection rate  = share of phishing URLs scored "Suspicious" or worse (>= 25)
  Strict rate     = share scored "Likely Phishing" (>= 55)
  False-alarm rate= share of legitimate URLs scored "Suspicious" or worse

Always evaluate on URLs that were NOT used for training or for tuning the rules,
otherwise the numbers are too good.
"""

import argparse
import collections

import engine
import scanner


def run(urls, use_ml=True):
    scores = []
    for u in urls:
        try:
            scores.append(scanner.scan_url(u, use_ml=use_ml)["score"])
        except ValueError:
            pass
    return scores


def pct(scores, thr):
    return 100.0 * sum(s >= thr for s in scores) / max(len(scores), 1)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Evaluate PhishGuard on real URL lists")
    ap.add_argument("--phish", nargs="+", required=True)
    ap.add_argument("--legit", nargs="+", required=True)
    ap.add_argument("--rules-only", action="store_true", help="also show the numbers without the ML model")
    a = ap.parse_args(argv)

    ph = [u for f in a.phish for u in scanner.read_url_file(f)]
    lg = [u for f in a.legit for u in scanner.read_url_file(f)]
    modes = [("Rules + ML", True)] + ([("Rules only", False)] if a.rules_only else [])
    for name, use_ml in modes:
        ps, ls = run(ph, use_ml), run(lg, use_ml)
        print(f"\n=== {name} ===")
        print(f"Phishing URLs tested : {len(ps)}")
        print(f"  detected (>= Suspicious)       : {pct(ps, engine.SUSPICIOUS_AT):5.1f}%")
        print(f"  strongly flagged (Likely Phish): {pct(ps, engine.PHISHING_AT):5.1f}%")
        print(f"Legitimate URLs tested: {len(ls)}")
        print(f"  false alarms (>= Suspicious)   : {pct(ls, engine.SUSPICIOUS_AT):5.1f}%")
        print(f"  false alarms (Likely Phishing) : {pct(ls, engine.PHISHING_AT):5.1f}%")
        tp, fn = sum(s >= 25 for s in ps), sum(s < 25 for s in ps)
        fp, tn = sum(s >= 25 for s in ls), sum(s < 25 for s in ls)
        rec = tp / max(tp + fn, 1)
        fpr = fp / max(fp + tn, 1)
        print(f"  balanced accuracy (average of detection rate and 1 - false-alarm rate): {(rec + 1 - fpr) / 2:.1%}")


if __name__ == "__main__":
    main()
