"""
Creates data/demo_urls.csv - a SYNTHETIC demo dataset (url,label).

  label 0 = legitimate-looking URL, label 1 = phishing-looking URL

IMPORTANT: this file is made by templates, NOT collected from the real internet.
It only exists so the app works out of the box.  Accuracy measured on it is NOT
a real-world accuracy.  For real numbers, train on a real dataset (see README):
    python train.py --data your_real_dataset.csv
"""

import csv
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
rng = random.Random(2026)

LEGIT_DOMAINS = """google.com youtube.com wikipedia.org amazon.in flipkart.com github.com stackoverflow.com
microsoft.com apple.com netflix.com linkedin.com bbc.com thehindu.com ndtv.com timesofindia.indiatimes.com
hdfcbank.com onlinesbi.sbi icicibank.com axisbank.com paytm.com irctc.co.in python.org mozilla.org reddit.com
medium.com quora.com coursera.org udemy.com nptel.ac.in swiggy.com zomato.com myntra.com bookmyshow.com
makemytrip.com goibibo.com naukri.com indeed.com hotstar.com spotify.com adobe.com zoom.us dropbox.com
cricbuzz.com espncricinfo.com moneycontrol.com economictimes.indiatimes.com tutorialspoint.com geeksforgeeks.org
w3schools.com khanacademy.org duolingo.com canva.com figma.com notion.so slack.com atlassian.com
oracle.com ibm.com intel.com nvidia.com samsung.com mi.com oneplus.in bajajfinserv.in lenskart.com nykaa.com
tatacliq.com bigbasket.com jiomart.com policybazaar.com cleartrip.com ola.com uber.com""".split()

LEGIT_PATHS = [
    "", "/", "/about", "/contact-us", "/help/faq", "/products/electronics/mobiles?brand=samsung&page=2",
    "/wiki/Machine_learning", "/watch?v={id}", "/news/national/{slug}/article{num}.ece",
    "/search?q=best+laptops+under+50000&page=3", "/user/profile/settings", "/docs/en/latest/index.html",
    "/login", "/account/orders?ref=nav", "/signin", "/cart", "/careers/jobs/software-engineer-{num}",
    "/blog/2026/10/{slug}", "/courses/python-for-beginners/lecture-{num}", "/dp/B0{num}XYZ?th=1&psc=1",
    "/story/{slug}-{num}.html", "/category/mens-wear/shirts?sort=popularity&price=500-1500",
    "/in/{slug}-{num}", "/r/learnprogramming/comments/{id}/{slug}/", "/issues/{num}", "/pricing",
    "/payment/status?order={num}&utm_source=email&utm_campaign=oct", "/security/update-policy",
]
SLUGS = ["how-to-learn-python-fast", "top-ten-travel-places-in-india", "budget-2026-key-highlights",
         "new-phone-launch-event", "exam-results-announced", "healthy-breakfast-ideas", "state-level-science-fair"]

BRANDS = ["paypal", "google", "facebook", "instagram", "whatsapp", "amazon", "microsoft", "apple", "netflix",
          "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "irctc", "flipkart"]
WORDS = ["login", "secure", "verify", "update", "account", "kyc", "support", "alert", "confirm", "banking",
         "wallet", "refund", "reward", "claim", "customer", "service", "official", "help"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "icu", "buzz", "cyou", "link", "work", "loan", "online", "site", "club"]
FREE = ["000webhostapp.com", "weebly.com", "web.app", "netlify.app", "github.io", "pages.dev", "herokuapp.com", "blogspot.com"]
PHISH_PATHS = ["/login.php", "/verify/account?id={num}", "/secure/update-kyc.html", "/signin?redirect={num}",
               "/wp-includes/js/confirm/index.php", "/netbanking/login", "/auth/session/{id}/verify", "/update/billing-info",
               "/claim-reward?user={num}", "/app/download/{slug}.apk", "/payment/otp-verify?txn={num}", "/", "/index.html",
               "/webscr?cmd=_login-submit&dispatch={id}", "/account/unlock?token={id}"]


def rid(n=11):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") for _ in range(n))


def fill(t):
    return t.format(id=rid(), num=rng.randint(100, 9999999), slug=rng.choice(SLUGS))


def typo(brand):
    b = list(brand)
    k = rng.choice(["sub", "dup", "drop", "num"])
    i = rng.randrange(len(b))
    if k == "sub":
        b[i] = {"o": "0", "l": "1", "i": "1", "a": "4", "e": "3", "s": "5"}.get(b[i], rng.choice("xqz"))
    elif k == "dup":
        b.insert(i, b[i])
    elif k == "drop" and len(b) > 4:
        del b[i]
    else:
        b.append(str(rng.randint(1, 99)))
    return "".join(b)


def legit():
    d = rng.choice(LEGIT_DOMAINS)
    host = ("www." if rng.random() < 0.5 else "") + d
    scheme = "https" if rng.random() < 0.92 else "http"
    return f"{scheme}://{host}{fill(rng.choice(LEGIT_PATHS))}"


def phish():
    kind = rng.choice(["brandword", "brandword", "typo", "ip", "subdomain", "free", "words", "shortlike", "at", "long"])
    brand, w1, w2 = rng.choice(BRANDS), rng.choice(WORDS), rng.choice(WORDS)
    tld = rng.choice(BAD_TLDS)
    if kind == "brandword":
        host = rng.choice([f"{brand}-{w1}.{tld}", f"{w1}-{brand}-{w2}.{tld}", f"{brand}{w1}.{tld}", f"{brand}.{w1}-{w2}.{tld}"])
    elif kind == "typo":
        host = f"{typo(brand)}.{rng.choice(['com', 'in', 'net', tld])}"
    elif kind == "ip":
        host = ".".join(str(rng.randint(1, 254)) for _ in range(4))
    elif kind == "subdomain":
        host = f"{brand}.com.{w1}.{w2}-{rng.randint(10, 99)}.{tld}"
    elif kind == "free":
        host = f"{brand}-{w1}-{rng.randint(10, 9999)}.{rng.choice(FREE)}"
    elif kind == "words":
        host = f"{w1}-{w2}-{rng.choice(WORDS)}.{tld}"
    elif kind == "shortlike":
        host = f"{rid(rng.randint(10, 16)).lower().replace('_', '').replace('-', '')}.{tld}"
    elif kind == "at":
        return f"http://{brand}.com@{rid(8).lower().replace('_', 'x').replace('-', 'y')}.{tld}{fill(rng.choice(PHISH_PATHS))}"
    else:
        host = f"{w1}.{w2}.{brand}.{rng.choice(WORDS)}.{tld}"
    scheme = "https" if rng.random() < 0.4 else "http"
    path = fill(rng.choice(PHISH_PATHS))
    if kind == "long":
        path += "/" + "/".join(rid(8) for _ in range(rng.randint(3, 6)))
    return f"{scheme}://{host}{path}"


def main(n_each=800):
    rows = [(legit(), 0) for _ in range(n_each)] + [(phish(), 1) for _ in range(n_each)]
    rng.shuffle(rows)
    os.makedirs(os.path.join(HERE, "data"), exist_ok=True)
    path = os.path.join(HERE, "data", "demo_urls.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(rows)
    print(f"Wrote {len(rows)} synthetic rows to {path}")


if __name__ == "__main__":
    main()
