# PhishGuard Pro - Python-Based Phishing URL & Message Detection System

PhishGuard Pro tells you whether a link (or a whole SMS / WhatsApp message) looks like
phishing, **and explains why**. It is written in **pure Python** - only the standard
library, nothing to install.

> It analyses the *text* of a URL and never opens the site (except the optional Deep Scan).
> It is a warning system, not proof. Measured results and limits: see **EVALUATION.md**.

## Quick start (IDLE)

1. Unzip the folder.
2. Open **IDLE** -> **File -> Open** -> choose `gui.py` inside the folder.
3. Press **F5** (Run -> Run Module). The PhishGuard Pro window opens.

Tests: open `run_tests.py` in IDLE and press **F5** (you should see `OK`).

## Try real examples

* **URL Scan tab -> "Real examples" drop-down**: 13 real phishing links from a public feed and 10 genuine sites.
* **Message Scan tab -> "Real-style examples" drop-down**: 10 typical Indian scam messages (KYC, electricity
  disconnection, India Post fee, income-tax refund, UPI cashback, task-job scam, fake APK ...) and 7 genuine
  messages (bank OTP, Google code, delivery OTP, UPI alert ...).
* **Batch Scan tab**: open `data/real_phishing_sample_60.txt` (60 real phishing URLs) or `data/real_legit_urls.txt`
  (106 genuine URLs), then export an HTML report.

**Never open the phishing links in a browser.** PhishGuard only reads them as text.

## What it does

| Tab | Purpose |
|---|---|
| URL Scan | Paste a link, get a verdict, a 0-100 risk score and the reasons |
| Message Scan | Paste an SMS / WhatsApp / e-mail; checks every link **and** scam wording. Understands that "Do not share this OTP" in a real bank SMS is a warning, not a scam |
| Batch Scan | Load a `.txt` / `.csv` of URLs, scan thousands, export CSV or an HTML report |
| History | Every scan is saved in a local SQLite database |
| Deep Scan (option) | Checks DNS, SSL certificate age/validity and redirect chain |

Verdicts: **0-24 Looks Safe | 25-54 Suspicious | 55-100 Likely Phishing**

## Measured accuracy (hidden real data, see EVALUATION.md)

* 9,481 real phishing URLs never seen before: **77 % flagged**, 22 % of them as "Likely Phishing"
* 3,106 genuine URLs: **2.3 % false alarms**, 0 % as "Likely Phishing"
* Most misses are normal-looking *hacked* websites - a URL check cannot see those.

## How the detection works

1. **Rule engine (`engine.py`)** - 30+ checks: IP / hex IP, `@` trick, look-alike & typosquatted domains
   (`paypa1.com`, `steancomnmuntiy.com`) via confusable-character normalisation + edit distance (also on
   subdomains), brand names inside someone else's domain, risky and cheap TLDs, URL shorteners,
   free-hosting / website-builder / tunnel services (pages.dev, duckdns, weebly ... - where most phishing lives
   today), hacked-CMS paths (`/wp-includes/`), punycode, random-looking domains, `.apk` / `.exe` links,
   open redirects, scam keywords. Well-known official domains are whitelisted to avoid false alarms.
2. **Machine learning (`ml.py`)** - logistic regression written from scratch (no numpy, no scikit-learn),
   trained on real phishing domains vs real popular domains. It looks at the registered domain name only
   (see the note in `ml.py` for why), can raise a score but never lower one, and cannot accuse alone.
3. **Message analysis (`messages.py`)** - extracts every link and scores scam language (urgency, KYC, OTP
   requests, fake prizes, parcel fees, APK installs, "contact this mobile number", task scams).
4. **Deep scan (`netcheck.py`)** - opt-in, headers only, nothing is downloaded or executed.

## Files

```
gui.py                  desktop app (run this)          cli.py            command line version
engine.py               rule-based analysis             ml.py             machine-learning model
messages.py             SMS / WhatsApp scanner          netcheck.py       optional deep scan
scanner.py              combines everything             storage.py        scan history (SQLite)
report.py               CSV + HTML reports              samples.py        real examples for the drop-downs
train.py                train + evaluate the model      real_eval.py      measure detection / false alarms
build_real_model.py     ONE COMMAND: download real data, train, final exam
make_demo_data.py       synthetic demo data (only for a quick offline demo)
test_phishguard.py      36 automated tests              run_tests.py      run them from IDLE
model.json              trained model                   EVALUATION.md     results + honest limits
data/                   real_legit_urls.txt, real_phishing_sample_60.txt, demo_urls.csv
```

## Re-train on fresh data (recommended before a presentation)

With internet on, open `build_real_model.py` in IDLE and press **F5** (about 2 minutes). It downloads a fresh
sample of real phishing URLs and popular domains, trains a new `model.json`, and prints the final exam on data
the model has never seen. Quote *those* numbers. (macOS note: if you see CERTIFICATE_VERIFY_FAILED, run
"Install Certificates.command" from your Python folder in Applications once.)

You can also train on your own dataset:
```
python train.py --data your_file.csv                      # url + label (good/bad) columns
python train.py --phish phishtank.csv --legit tranco.csv
```
`train.py` splits **by website** (a site is either in training or in the test, never both), caps rows per site,
and warns about dataset bias.

## Command line

```
python cli.py https://www.google.com http://paypal.secure-login.xyz
python cli.py --message "Your SBI account will be blocked. Update KYC: http://sbi-kyc.xyz"
python cli.py --file data/real_phishing_sample_60.txt --html report.html --csv report.csv
python cli.py URL --deep --json
```

## Honest limits

* A URL-text check can miss phishing on a clean-looking or hacked legitimate domain.
* It can flag unusual but legitimate links (long tracking URLs, personal sites on free hosting).
* The whitelist covers well-known sites only; a brand-new genuine site may look "suspicious".
* Deep Scan contacts the website, so it reveals your IP address to that site. Leave it off for unknown links.
* Never type a password on a link you are unsure about - open the official app or type the official address yourself.

## Ideas to extend (still pure Python)

* More brands / bank domains in `OFFICIAL` (your state's banks and government portals)
* Domain-age check through a WHOIS lookup (raw socket on port 43)
* A small local web server (`http.server`) so a browser extension or a school network can query the engine
* Compare logistic regression with naive Bayes on the same data
