"""
PhishGuard Pro - machine-learning model (written from scratch, pure Python)
===========================================================================
Logistic regression trained with stochastic gradient descent.

WHAT THE MODEL LOOKS AT: the registered DOMAIN NAME only (e.g. 'paypal-login.xyz'), as
  * ~15 numeric features from engine.py (length, hyphens, digits, entropy, TLD ...), and
  * hashed character 3-grams of the host (catches words like "secure-login").
The rule engine separately judges subdomains, path, query string, scheme and so on.

WHY HOST ONLY: real, current phishing URLs and the big public lists of legitimate
sites do not look alike in paths, schemes or era. A model that sees them learns
those dataset differences instead of phishing (we measured this: it raised false
alarms on 61 % of normal modern links). On the domain name both sides are
comparable, so that is where the model learns honestly.

No numpy / scikit-learn needed, so it runs in plain IDLE.
"""

import csv
import json
import math
import random
import time
import zlib

import engine

HASH_DIM = 2048
ML_FEATURES = [
    "host_len", "dots_host", "hyphens_host", "digits_host", "digit_ratio", "subdomains",
    "is_ip", "entropy_host", "kw_count", "risky_tld", "shortener", "nonascii_host",
    "brand_abuse", "typosquat", "free_host",
]

PHISH_WORDS = {"bad", "phishing", "phish", "malicious", "malware", "defacement", "1", "true", "yes"}
LEGIT_WORDS = {"good", "legit", "legitimate", "benign", "safe", "0", "false", "no"}


# ----------------------------------------------------------------------
# Features
# ----------------------------------------------------------------------
def _grams(host: str, n: int = 3) -> dict:
    s = host.strip().lower()
    if s.startswith("www."):
        s = s[4:]
    ids = {zlib.crc32(s[i:i + n].encode("utf-8", "ignore")) % HASH_DIM for i in range(max(len(s) - n + 1, 0))}
    if not ids:
        return {}
    v = 3.0 / math.sqrt(len(ids))
    return {i: v for i in ids}


def featurize(url: str):
    """Numeric features + hashed n-grams of the registered DOMAIN only (e.g. 'paypal-login.xyz').
    Path, query, scheme and subdomains are ignored on purpose - see the note at the top."""
    host = engine.parse_url(url).reg
    a = engine.analyze("http://" + host)
    return [float(a.features[n]) for n in ML_FEATURES], _grams(host)


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


# ----------------------------------------------------------------------
# Training / prediction
# ----------------------------------------------------------------------
def train(rows, epochs: int = 15, lr: float = 0.05, l2: float = 1e-6, seed: int = 7, verbose: bool = False):
    """rows: list of (url, label) with label 1 = phishing, 0 = legitimate."""
    data = []
    for url, y in rows:
        try:
            nums, grams = featurize(url)
        except ValueError:
            continue
        data.append((nums, grams, int(y)))
    if len(data) < 20:
        raise ValueError("Need at least 20 usable rows to train.")

    nf = len(ML_FEATURES)
    mean = [sum(d[0][k] for d in data) / len(data) for k in range(nf)]
    std = [math.sqrt(sum((d[0][k] - mean[k]) ** 2 for d in data) / len(data)) or 1.0 for k in range(nf)]
    data = [([max(-5.0, min(5.0, (x[k] - mean[k]) / std[k])) for k in range(nf)], g, y) for x, g, y in data]

    wn, wg, b = [0.0] * nf, [0.0] * HASH_DIM, 0.0
    rng = random.Random(seed)
    for ep in range(epochs):
        rng.shuffle(data)
        rate = lr / (1 + 0.15 * ep)
        loss = 0.0
        for xs, grams, y in data:
            z = b + sum(wn[k] * xs[k] for k in range(nf)) + sum(wg[i] * v for i, v in grams.items())
            p = _sigmoid(z)
            loss += -math.log(max(p if y else 1 - p, 1e-12))
            g = p - y
            for k in range(nf):
                wn[k] -= rate * (g * xs[k] + l2 * wn[k])
            for i, v in grams.items():
                wg[i] -= rate * (g * v + l2 * wg[i])
            b -= rate * g
        if verbose:
            print(f"  epoch {ep + 1:2d}/{epochs}  loss {loss / len(data):.4f}")

    return {
        "version": 1, "features": ML_FEATURES, "mean": mean, "std": std,
        "wn": [round(w, 5) for w in wn], "wg": [round(w, 5) for w in wg], "b": round(b, 5),
        "meta": {"trained_on": len(data), "epochs": epochs, "created": time.strftime("%Y-%m-%d %H:%M")},
    }


def predict(model: dict, url: str) -> float:
    """Probability (0..1) that the URL is phishing."""
    if model["features"] != ML_FEATURES:
        raise ValueError("Model was trained with different features - please retrain.")
    nums, grams = featurize(url)
    z = model["b"]
    for k, x in enumerate(nums):
        xs = max(-5.0, min(5.0, (x - model["mean"][k]) / model["std"][k]))
        z += model["wn"][k] * xs
    wg = model["wg"]
    z += sum(wg[i] * v for i, v in grams.items())
    return _sigmoid(z)


def evaluate(model: dict, rows) -> dict:
    tp = fp = tn = fn = 0
    for url, y in rows:
        try:
            pred = predict(model, url) >= 0.5
        except ValueError:
            continue
        if y and pred:
            tp += 1
        elif y and not pred:
            fn += 1
        elif not y and pred:
            fp += 1
        else:
            tn += 1
    total = max(tp + fp + tn + fn, 1)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "accuracy": (tp + tn) / total,
            "precision": prec, "recall": rec, "f1": f1, "n": tp + fp + tn + fn}


def split(rows, test_fraction: float = 0.2, seed: int = 42):
    rows = list(rows)
    random.Random(seed).shuffle(rows)
    cut = int(len(rows) * (1 - test_fraction))
    return rows[:cut], rows[cut:]


# ----------------------------------------------------------------------
# Load / save
# ----------------------------------------------------------------------
def save_model(model: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(model, f)


def load_model(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            m = json.load(f)
        return m if m.get("features") == ML_FEATURES else None
    except (OSError, ValueError):
        return None


def load_rows(path: str, default_label=None):
    """
    Read a CSV of URLs.  Understands:
      * header with a url/domain column and a label/class/type/status column
        (e.g. Kaggle 'Phishing Site URLs': URL,Label with good/bad)
      * header-less or label-less files when default_label is given
        (e.g. a PhishTank export -> default_label=1, a Tranco list -> default_label=0)
    """
    rows, bad = [], 0
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        first = next(reader, None)
        if first is None:
            return rows
        names = [c.strip().lower() for c in first]
        url_i = next((i for i, n in enumerate(names) if n in ("url", "urls", "link", "domain")), None)
        lab_i = next((i for i, n in enumerate(names) if n in ("label", "class", "type", "status", "result", "target")), None)
        header = url_i is not None
        body = reader if header else _chain(first, reader)
        for r in body:
            if not r:
                continue
            if header:
                url = r[url_i].strip() if url_i < len(r) else ""
                lab = r[lab_i].strip().lower() if lab_i is not None and lab_i < len(r) else None
            else:
                cell = next((c.strip() for c in r if "." in c and not c.strip().replace(".", "").isdigit()), "")
                url, lab = cell, (r[1].strip().lower() if default_label is None and len(r) > 1 else None)
            if not url:
                continue
            if lab in PHISH_WORDS:
                y = 1
            elif lab in LEGIT_WORDS:
                y = 0
            elif default_label is not None:
                y = int(default_label)
            else:
                bad += 1
                continue
            rows.append((url, y))
    return rows


def _chain(first, rest):
    yield first
    yield from rest
