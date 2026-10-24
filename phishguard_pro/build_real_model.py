"""
ONE COMMAND to train and honestly evaluate PhishGuard on REAL data.

    python build_real_model.py          (or open in IDLE and press F5)

What it does
  1. Downloads (a) a spread-out sample of real phishing URLs from the open-source
     Phishing.Database project and (b) a list of the world's most popular domains.
  2. Splits them: half of the phishing URLs and 12,000 popular domains are used to TRAIN
     the model; the other half / another 3,000 domains are kept hidden for the final exam.
  3. Trains the model, then prints detection rate and false-alarm rate on the hidden data.

Needs internet. Never visits any phishing URL - it only downloads text lists from GitHub.
If you see an SSL certificate error on macOS: open
  /Applications/Python 3.x/Install Certificates.command   once, then run this again.
"""

import os
import random
import re
import sys
import urllib.request

import ml
import real_eval
import scanner
import train

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "real")

PHISH_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
LEGIT_URL = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains"
CHUNKS, CHUNK_BYTES = 14, 120_000


def _open(req):
    try:
        return urllib.request.urlopen(req, timeout=60)
    except Exception as e:                                    # noqa: BLE001
        sys.exit(f"\nDownload failed: {e}\n"
                 "Check your internet connection. On macOS, if it mentions CERTIFICATE_VERIFY_FAILED, run\n"
                 "'Install Certificates.command' from your Python folder in Applications, then try again.")


def download_phishing():
    print("Downloading a spread-out sample of real phishing URLs ...")
    head = _open(urllib.request.Request(PHISH_URL, method="HEAD"))
    size = int(head.headers["Content-Length"])
    seen, urls = set(), []
    for i in range(CHUNKS):
        start = int(size * i / CHUNKS)
        req = urllib.request.Request(PHISH_URL, headers={"Range": f"bytes={start}-{start + CHUNK_BYTES}"})
        text = _open(req).read().decode("utf-8", "ignore")
        for line in text.split("\n")[1:-1]:                   # first/last lines are cut off
            line = line.strip()
            if re.match(r"https?://", line, re.I) and " " not in line and line.lower() not in seen:
                seen.add(line.lower())
                urls.append(line)
        print(f"  part {i + 1}/{CHUNKS}  ({len(urls)} unique URLs so far)")
    return urls


def download_legit():
    print("Downloading the list of popular domains (about 15 MB) ...")
    text = _open(urllib.request.Request(LEGIT_URL)).read().decode("utf-8", "ignore")
    return [d.strip() for d in text.split("\n") if "." in d]


def write(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    os.makedirs(OUT, exist_ok=True)
    ph = download_phishing()
    random.Random(11).shuffle(ph)
    half = len(ph) // 2
    write(os.path.join(OUT, "phish_train.txt"), ph[:half])
    write(os.path.join(OUT, "phish_holdout.txt"), ph[half:])

    lg = download_legit()
    random.Random(5).shuffle(lg)
    write(os.path.join(OUT, "legit_train.txt"), lg[:12000])
    write(os.path.join(OUT, "legit_test.txt"), lg[12000:15000])
    print(f"\nSaved data files in {OUT}\n  phishing: {half} to train, {len(ph) - half} hidden   legit: 12000 to train, 3000 hidden")

    model = train.main([
        "--phish", os.path.join(OUT, "phish_train.txt"),
        "--legit", os.path.join(OUT, "legit_train.txt"),
        "--cap-per-domain", "10", "--per-class", "8000",
        "--test-phish", os.path.join(OUT, "phish_holdout.txt"),
        "--test-legit", os.path.join(OUT, "legit_test.txt"),
    ])
    model["meta"]["source"] = f"real data: {half} phishing URLs (Phishing.Database sample) + 12,000 popular domains (Top-1M list)"
    ml.save_model(model, scanner.MODEL_PATH)
    scanner.reload_model()

    print("\n\n######## FINAL EXAM: the whole system on data it never saw ########")
    real_eval.main([
        "--phish", os.path.join(OUT, "phish_holdout.txt"),
        "--legit", os.path.join(HERE, "data", "real_legit_urls.txt"), os.path.join(OUT, "legit_test.txt"),
        "--rules-only",
    ])
    print("\nThese are the numbers to quote in your report. Restart the app to use the new model.")


if __name__ == "__main__":
    main()
