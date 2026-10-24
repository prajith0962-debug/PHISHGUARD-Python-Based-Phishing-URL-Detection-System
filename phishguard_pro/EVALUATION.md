# PhishGuard Pro - Evaluation on real data

All numbers below come from `build_real_model.py` / `real_eval.py` and can be reproduced with
`python build_real_model.py` (needs internet; it only downloads text lists from GitHub).

## Data
| Purpose | Source | Size |
|---|---|---|
| Phishing (train) | Phishing.Database "ACTIVE links" list, spread-out sample, MIT licence | 9,480 URLs |
| Phishing (hidden test) | same list, other half, never used for training or for designing rules | 9,481 URLs |
| Legitimate (train) | "Top 1,000,000 domains" list, random sample | 12,000 domains |
| Legitimate (hidden test) | same list, different random sample | 3,000 domains |
| Legitimate (hand-made) | 106 genuine, realistic URLs (Google, SBI, IRCTC, GitHub, ...) in `data/real_legit_urls.txt` | 106 URLs |

## Result on the hidden test data (whole system)

| | Detected as Suspicious or worse | Detected as Likely Phishing |
|---|---|---|
| **Real phishing URLs (9,481)** - rules + ML | **77.2 %** | **22.2 %** |
| Real phishing URLs - rules only | 52.4 % | 6.7 % |

| | False alarm (Suspicious or worse) | False alarm (Likely Phishing) |
|---|---|---|
| **Genuine URLs (3,106)** - rules + ML | **2.3 %** | **0.0 %** |
| Genuine URLs - rules only | 0.4 % | 0.0 % |

Balanced accuracy (average of detection rate and 1 - false-alarm rate): **87.5 %** (rules only: 76.0 %).

The ML model adds about 25 points of detection for about 2 points of extra false alarms.
It can only raise a score, never lower one, and cannot make a link "Suspicious" without help from the rules.

### The ML model alone (domain name only)
* On websites it had never seen (same dataset): accuracy 73.3 %, precision 70.9 %, recall 56.5 %.
* On the hidden phishing URLs: catches 81.8 % - but also raises a false alarm on 16.0 % of genuine domains.
  A domain name alone is a weak signal, which is why the model is only a helper to the rules.

## Messages (SMS / WhatsApp)
17 hand-written examples (`samples.py`): 10 typical Indian scam messages, 7 genuine messages from banks,
Google, Amazon, UPI, electricity, IRCTC and a college. All 10 scams flagged, all genuine messages "Looks Safe"
(an automated test checks this). This is a small regression set, NOT a statistical accuracy figure.

## Honest limits - read before quoting any number
1. **Most missed phishing pages sit on normal-looking, hacked websites** (a shop, a school, a blog). Nothing in
   the URL text reveals them. Catching these needs page content or reputation data (Deep Scan helps a little).
2. The phishing list comes from a public feed and was **not manually verified**; some entries are stale or mislabelled.
3. The hidden phishing half shares hosting services (pages.dev, duckdns, weebly ...) with the training half. The
   result therefore measures "new phishing URLs on the kinds of infrastructure attackers use today", not
   "a brand-new attack technique".
4. The genuine-URL test is mostly **popular** domains without paths. Real false-alarm rates on unknown small websites
   and very long genuine links can be higher.
5. The 106 hand-made genuine URLs were used while tuning the rules to avoid false alarms, so that part is slightly optimistic.
6. A first quick test on the first 3,300 lines of the feed showed 99 %. That was misleading: the file is sorted
   alphabetically, so those lines were not representative. A sample spread over the whole file gave the numbers above.
   Lesson: always test on a representative sample.
7. Phishing changes daily. Re-run `build_real_model.py` regularly.
