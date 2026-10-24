"""
PhishGuard Pro - export scan results as CSV or a stand-alone HTML report
"""

import csv
import html
import time

COLORS = {"Looks Safe": "#1e8e3e", "Suspicious": "#b06f00", "Likely Phishing": "#d93025"}


def to_csv(results, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "verdict", "score", "rule_score", "ml_probability", "reasons"])
        for r in results:
            ml = "" if r.get("ml_prob") is None else f"{r['ml_prob']:.3f}"
            w.writerow([r["url"], r["verdict"], r["score"], r["rule_score"], ml, " | ".join(r["reasons"])])


def to_html(results, path: str, title: str = "PhishGuard Pro - Scan Report") -> None:
    counts = {k: 0 for k in COLORS}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    rows = []
    for r in sorted(results, key=lambda r: -r["score"]):
        c = COLORS.get(r["verdict"], "#444")
        why = "".join(f"<li>{html.escape(x)}</li>" for x in r["reasons"])
        rows.append(
            f"<tr><td class='u'>{html.escape(r['url'])}</td>"
            f"<td style='color:{c};font-weight:700'>{html.escape(r['verdict'])}</td>"
            f"<td>{r['score']}</td><td><ul>{why}</ul></td></tr>"
        )
    summary = " &nbsp;|&nbsp; ".join(
        f"<b style='color:{COLORS[k]}'>{k}: {v}</b>" for k, v in counts.items() if k in COLORS
    )
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px;color:#1f2328;background:#fff}}
h1{{margin:0 0 4px}} .sub{{color:#57606a;margin-bottom:16px}}
table{{border-collapse:collapse;width:100%}} th,td{{border-bottom:1px solid #d0d7de;padding:8px;text-align:left;vertical-align:top}}
th{{background:#f6f8fa}} td.u{{word-break:break-all;font-family:ui-monospace,Consolas,monospace;font-size:13px}}
ul{{margin:0;padding-left:18px}} .note{{margin-top:18px;color:#57606a;font-size:13px}}
</style></head><body>
<h1>{html.escape(title)}</h1>
<div class="sub">Generated {time.strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp; {len(results)} URL(s) &nbsp;|&nbsp; {summary}</div>
<table><tr><th>URL</th><th>Verdict</th><th>Score</th><th>Why</th></tr>{''.join(rows)}</table>
<p class="note">Preliminary automated analysis of the URL text. It cannot prove a site is phishing or safe.</p>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
