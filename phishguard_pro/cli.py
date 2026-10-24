"""
PhishGuard Pro - command-line interface

    python cli.py https://example.com http://paypal.secure-login.xyz
    python cli.py --message "Your SBI account will be blocked. Update KYC: http://sbi-kyc.xyz"
    python cli.py --file urls.txt --html report.html
    python cli.py URL --deep            # also checks DNS / SSL certificate / redirects
    python cli.py URL --json
"""

import argparse
import json
import sys

import messages
import report
import scanner

ICON = {"Looks Safe": "[ OK ]", "Suspicious": "[WARN]", "Likely Phishing": "[DANGER]"}


def show(r):
    print("-" * 64)
    print(f"URL      : {r['url']}")
    print(f"Verdict  : {ICON[r['verdict']]} {r['verdict']}   (risk {r['score']}/100)")
    ml = "n/a" if r["ml_prob"] is None else f"{r['ml_prob']:.0%}"
    print(f"Rules    : {r['rule_score']}/100     ML probability: {ml}")
    print("Reasons  :")
    for x in r["reasons"]:
        print(f"   - {x}")
    if r.get("deep"):
        for n in r["deep"]["notes"]:
            print(f"   (deep scan) {n}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="PhishGuard Pro - phishing URL / message detector")
    ap.add_argument("urls", nargs="*")
    ap.add_argument("--file", help=".txt or .csv with URLs")
    ap.add_argument("--message", help="scan a pasted SMS/WhatsApp message")
    ap.add_argument("--deep", action="store_true", help="contact the site: DNS, SSL, redirects")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--csv", help="write results to CSV")
    ap.add_argument("--html", help="write results to an HTML report")
    a = ap.parse_args(argv)

    if a.message:
        m = messages.scan_message(a.message, deep=a.deep)
        if a.json:
            print(json.dumps(m, indent=2, default=str))
        else:
            print(f"MESSAGE VERDICT: {ICON[m['verdict']]} {m['verdict']} ({m['score']}/100)")
            for x in m["reasons"]:
                print(f"   - {x}")
            for r in m["links"]:
                show(r)
        return 0

    urls = list(a.urls)
    if a.file:
        urls += scanner.read_url_file(a.file)
    if not urls:
        ap.print_help()
        return 1
    results, errors = scanner.scan_many(urls, deep=a.deep)
    if a.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        for r in results:
            show(r)
        for u, e in errors:
            print(f"Skipped '{u}': {e}", file=sys.stderr)
    if a.csv:
        report.to_csv(results, a.csv)
    if a.html:
        report.to_html(results, a.html)
    return 0


if __name__ == "__main__":
    sys.exit(main())
