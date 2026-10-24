"""
Train and evaluate the PhishGuard ML model.

Examples (terminal, or press F5 in IDLE to train on the demo data):
    python train.py                                          # demo (synthetic) data
    python train.py --data data.csv                          # CSV with url + label (good/bad)
    python train.py --data data.csv --phish phish_feed.txt   # add more real phishing URLs
    python train.py --phish phishtank.csv --legit tranco.csv

How the evaluation stays honest
  * Rows are limited per website (--cap-per-domain) so one big site cannot dominate.
  * The 80/20 split is done BY WEBSITE: a domain is either in training or in the test
    set, never both.  (A random split would let the model "remember" sites and
    would inflate the accuracy.)
  * You can also evaluate on files the model never saw (--test-phish, --test-legit).
"""

import argparse
import os
import random

import engine
import ml
import scanner

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO = os.path.join(HERE, "data", "demo_urls.csv")


def _has_path(url):
    u = url.split("://", 1)[-1]
    return "/" in u.rstrip("/") or "?" in u


def _key(url):
    try:
        return engine.parse_url(url).reg
    except ValueError:
        return None


def cap_per_domain(rows, cap, rng):
    by = {}
    for url, y in rows:
        k = _key(url)
        if k:
            by.setdefault((k, y), []).append((url, y))
    out = []
    for items in by.values():
        rng.shuffle(items)
        out += items[:cap]
    return out


def group_split(rows, test_fraction, rng):
    groups = sorted({_key(u) for u, _ in rows})
    rng.shuffle(groups)
    test_groups = set(groups[: int(len(groups) * test_fraction)])
    train, test = [], []
    for r in rows:
        (test if _key(r[0]) in test_groups else train).append(r)
    return train, test


def read_urls(path):
    return [u for u in scanner.read_url_file(path) if u]


def report(title, m):
    print(f"\n--- {title} ---")
    print(f"  rows {m['n']}   accuracy {m['accuracy']:.1%}   precision {m['precision']:.1%}   recall {m['recall']:.1%}   F1 {m['f1']:.1%}")
    print(f"  confusion: TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Train the PhishGuard ML model")
    ap.add_argument("--data", nargs="*", default=[], help="CSV file(s) with url + label columns")
    ap.add_argument("--phish", nargs="*", default=[], help="file(s) of phishing URLs (label-less)")
    ap.add_argument("--legit", nargs="*", default=[], help="file(s) of legitimate URLs/domains (label-less)")
    ap.add_argument("--test-phish", help="phishing URLs the model never sees; reports how many it catches")
    ap.add_argument("--test-legit", help="legitimate URLs the model never sees; reports false alarms")
    ap.add_argument("--cap-per-domain", type=int, default=3)
    ap.add_argument("--per-class", type=int, default=20000, help="max rows per class after capping (0 = all)")
    ap.add_argument("--epochs", type=int, default=15)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)
    rng = random.Random(args.seed)

    rows, source = [], []
    for p in args.data:
        rows += ml.load_rows(p)
        source.append(os.path.basename(p))
    for p in args.phish:
        rows += ml.load_rows(p, default_label=1)
        source.append(os.path.basename(p))
    for p in args.legit:
        rows += ml.load_rows(p, default_label=0)
        source.append(os.path.basename(p))
    if not rows:
        if not os.path.exists(DEMO):
            import make_demo_data
            make_demo_data.main()
        rows = ml.load_rows(DEMO)
        source = ["demo-synthetic"]
    source = " + ".join(source)

    pos = sum(1 for _, y in rows if y)
    print(f"Loaded {len(rows)} rows ({pos} phishing, {len(rows) - pos} legitimate) from: {source}")
    rows = cap_per_domain(rows, args.cap_per_domain, rng)
    if args.per_class:
        a = [r for r in rows if r[1] == 1]
        b = [r for r in rows if r[1] == 0]
        rng.shuffle(a)
        rng.shuffle(b)
        rows = a[: args.per_class] + b[: args.per_class]
    pos = sum(1 for _, y in rows if y)
    print(f"After capping to {args.cap_per_domain} per website and balancing: {len(rows)} rows ({pos} phishing, {len(rows) - pos} legitimate)")
    if min(pos, len(rows) - pos) < 10:
        raise SystemExit("Need both classes (at least 10 rows each).")

    pr = sum(_has_path(u) for u, y in rows if y) / max(pos, 1)
    lr = sum(_has_path(u) for u, y in rows if not y) / max(len(rows) - pos, 1)
    if abs(pr - lr) > 0.4:
        print(f"WARNING: {pr:.0%} of phishing rows have a path but only {lr:.0%} of legit rows do.")
        print("         The model may learn that bias instead of real phishing signals. Use full URLs for both classes.")

    train_rows, test_rows = group_split(rows, 0.2, rng)
    print(f"Training on {len(train_rows)} rows, testing on {len(test_rows)} rows from websites it has never seen ...")
    model = ml.train(train_rows, epochs=args.epochs, verbose=True)
    m = ml.evaluate(model, test_rows)
    report("Held-out websites (same dataset)", m)

    extra = {}
    if args.test_phish:
        urls = read_urls(args.test_phish)
        e = ml.evaluate(model, [(u, 1) for u in urls])
        print(f"\n--- Fresh real phishing URLs the model never saw ({args.test_phish}) ---")
        print(f"  ML alone catches {e['recall']:.1%} of {e['n']}")
        extra["fresh_phish_recall_ml_only"] = e["recall"]
    if args.test_legit:
        urls = read_urls(args.test_legit)
        e = ml.evaluate(model, [(u, 0) for u in urls])
        fp = e["fp"] / max(e["n"], 1)
        print(f"\n--- Real legitimate URLs the model never saw ({args.test_legit}) ---")
        print(f"  ML alone raises a false alarm on {fp:.1%} of {e['n']}")
        extra["fresh_legit_false_alarm_ml_only"] = fp

    if source == "demo-synthetic":
        print("\nNOTE: demo data is synthetic, so these numbers are NOT real-world accuracy.")

    model["meta"].update({"source": source, "metrics": m, "extra": extra})
    ml.save_model(model, scanner.MODEL_PATH)
    print(f"\nModel saved to {scanner.MODEL_PATH}")
    scanner.reload_model()
    return model


if __name__ == "__main__":
    main()
