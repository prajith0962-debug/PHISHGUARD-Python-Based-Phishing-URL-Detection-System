"""
PhishGuard Pro - scanner (combines rules + ML + optional deep scan)
"""

import csv
import os

import engine
import ml

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "model.json")

# If the rules see (almost) nothing wrong, the ML model alone may not push a URL
# past this score.  This keeps false alarms low; the model confirms, it doesn't accuse alone.
ML_ALONE_CAP = 24

_cache = {"model": None, "loaded": False}


def get_model():
    if not _cache["loaded"]:
        _cache["model"] = ml.load_model(MODEL_PATH)
        _cache["loaded"] = True
    return _cache["model"]


def reload_model():
    _cache["loaded"] = False
    return get_model()


def scan_url(url: str, deep: bool = False, use_ml: bool = True) -> dict:
    """Analyse one URL. Raises ValueError for unusable input."""
    a = engine.analyze(url)
    findings = list(a.findings)
    deep_info = None
    if deep:
        import netcheck
        deep_info = netcheck.deep_scan(url)
        findings += deep_info["findings"]

    rule = min(100, sum(p for p, _ in findings))
    reasons = [r for _, r in sorted(findings, key=lambda f: -f[0]) if r]

    ml_prob = None
    model = get_model() if use_ml and not a.trusted else None
    if model is not None:
        ml_prob = ml.predict(model, url)
        blended = 0.7 * rule + 0.3 * ml_prob * 100
        final = max(blended, rule)   # ML can raise a score, never talk the rules down
        if rule < 10:
            final = min(final, ML_ALONE_CAP)
        if ml_prob >= 0.8:
            reasons.append(f"ML model: the URL text strongly resembles known phishing URLs ({ml_prob:.0%}).")
        elif ml_prob >= 0.5:
            reasons.append(f"ML model: the URL text somewhat resembles phishing URLs ({ml_prob:.0%}).")
    else:
        final = float(rule)
    final = int(round(min(100, final)))
    if a.trusted:
        final = min(final, 5)
    if not reasons:
        reasons = ["No suspicious patterns detected."]

    p = a.parsed
    return {
        "url": p.raw, "verdict": engine.verdict_for(final), "score": final,
        "rule_score": rule, "ml_prob": ml_prob, "reasons": reasons, "trusted": a.trusted,
        "details": {
            "host": p.host, "registered_domain": p.reg, "scheme": p.scheme or "(none)",
            "url_length": len(p.raw), "subdomains": a.features["subdomains"],
            "host_entropy": round(a.features["entropy_host"], 2),
        },
        "deep": deep_info,
    }


def read_url_file(path: str):
    """URLs from a .txt (one per line) or .csv (a 'url' column, else first column)."""
    urls = []
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        if path.lower().endswith(".csv"):
            rows = list(csv.reader(f))
            if not rows:
                return urls
            names = [c.strip().lower() for c in rows[0]]
            if "url" in names:
                i = names.index("url")
                urls = [r[i].strip() for r in rows[1:] if len(r) > i and r[i].strip()]
            else:
                urls = [r[0].strip() for r in rows if r and r[0].strip()]
        else:
            urls = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    return urls


def scan_many(urls, deep=False):
    """Returns (results, errors) where errors is a list of (url, message)."""
    results, errors = [], []
    for u in urls:
        try:
            results.append(scan_url(u, deep=deep))
        except ValueError as e:
            errors.append((u, str(e)))
    return results, errors
