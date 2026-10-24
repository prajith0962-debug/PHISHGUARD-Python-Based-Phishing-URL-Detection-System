"""
Automated tests for PhishGuard Pro.
Run:  python -m unittest -v      (or open run_tests.py in IDLE and press F5)
"""

import csv
import os
import tempfile
import unittest

import engine
import messages
import ml
import report
import scanner
import storage

LEGIT = [
    "https://www.google.com",
    "https://accounts.google.com/signin",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://github.com/python/cpython/issues/12345",
    "https://www.amazon.in/dp/B09XYZ1234?ref=nav_signin",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://onlinesbi.sbi/",
    "https://www.irctc.co.in/nget/train-search",
    "https://my-college-portal.ac.in/student/result?roll=21CS045",
    "https://www.healthline.com/nutrition/10-health-benefits-of-turmeric",
    "https://docs.python.org/3/library/urllib.parse.html",
]
PHISH = [
    "http://paypal.secure-login.xyz/verify",
    "http://sbi-kyc-update.xyz/login",
    "http://secure-hdfc-bank.top/netbanking/login.php",
    "https://paypal.com.account-verify.xyz/login",
    "http://192.168.10.5/login/verify",
    "https://paypal-account-verify.weebly.com/login",
]


class TestEngine(unittest.TestCase):
    def test_legit_urls_are_safe(self):
        for u in LEGIT:
            r = scanner.scan_url(u)
            self.assertEqual(r["verdict"], "Looks Safe", f"{u} -> {r['score']} {r['reasons']}")

    def test_phishing_urls_are_flagged(self):
        for u in PHISH:
            r = scanner.scan_url(u)
            self.assertEqual(r["verdict"], "Likely Phishing", f"{u} -> {r['score']} {r['reasons']}")

    def test_training_example_is_suspicious(self):
        self.assertIn(scanner.scan_url("http://example-login-security.test")["verdict"], ("Suspicious", "Likely Phishing"))

    def test_typosquatting(self):
        for u in ("https://paypa1.com/signin", "https://g00gle.com", "https://www.arnazon.in/login"):
            a = engine.analyze(u)
            self.assertEqual(a.features["typosquat"], 1, u)
            self.assertGreaterEqual(a.rule_score, 25, u)

    def test_official_domains_not_typosquat(self):
        for u in ("https://www.paypal.com", "https://sbi.co.in", "https://www.amazon.in"):
            self.assertEqual(engine.analyze(u).features["typosquat"], 0, u)

    def test_at_trick_and_hidden_host(self):
        a = engine.analyze("https://google.com@evil.example/")
        self.assertEqual(a.parsed.host, "evil.example")
        self.assertTrue(any("'@'" in r for r in a.reasons))

    def test_obfuscated_ip(self):
        self.assertEqual(engine.analyze("http://0x7f000001/a").features["is_ip"], 1)
        self.assertEqual(engine.analyze("http://2130706433/a").features["is_ip"], 1)

    def test_punycode(self):
        self.assertTrue(any("punycode" in r.lower() for r in engine.analyze("https://xn--pple-43d.com/").reasons))

    def test_apk_download(self):
        self.assertTrue(any(".apk" in r for r in engine.analyze("http://free-offer.example.top/get/app.apk").reasons))

    def test_registered_domain(self):
        self.assertEqual(engine.registered_domain("login.paypal.com"), "paypal.com")
        self.assertEqual(engine.registered_domain("www.sbi.co.in"), "sbi.co.in")

    def test_user_content_hosts_are_not_fully_trusted(self):
        a = engine.analyze("https://docs.google.com/forms/d/e/abc/viewform")
        self.assertFalse(a.trusted)

    def test_invalid_input(self):
        for bad in ("", "   ", "has space.com", "http://"):
            with self.assertRaises(ValueError):
                scanner.scan_url(bad)

    def test_levenshtein(self):
        self.assertEqual(engine.levenshtein("kitten", "sitting"), 3)
        self.assertEqual(engine.levenshtein("abc", "abc"), 0)


class TestML(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = [(u, 0) for u in LEGIT * 6] + [(u, 1) for u in PHISH * 6]
        cls.model = ml.train(rows, epochs=8)

    def test_learns_training_data(self):
        m = ml.evaluate(self.model, [(u, 0) for u in LEGIT] + [(u, 1) for u in PHISH])
        self.assertGreaterEqual(m["accuracy"], 0.9)

    def test_probability_range(self):
        for u in LEGIT + PHISH:
            self.assertTrue(0.0 <= ml.predict(self.model, u) <= 1.0)

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.json")
            ml.save_model(self.model, p)
            loaded = ml.load_model(p)
            self.assertAlmostEqual(ml.predict(self.model, PHISH[0]), ml.predict(loaded, PHISH[0]), places=6)

    def test_split_and_load_rows(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "kaggle_style.csv")
            with open(p, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["URL", "Label"])
                w.writerow(["https://good.example.com/a", "good"])
                w.writerow(["http://bad.example.xyz/login", "bad"])
                w.writerow(["http://skip.me", "unknown"])
            rows = ml.load_rows(p)
            self.assertEqual(rows, [("https://good.example.com/a", 0), ("http://bad.example.xyz/login", 1)])
            q = os.path.join(d, "labelless.csv")
            with open(q, "w", newline="") as f:
                csv.writer(f).writerows([["1", "google.com"], ["2", "wikipedia.org"]])
            self.assertEqual(ml.load_rows(q, default_label=0), [("google.com", 0), ("wikipedia.org", 0)])
        a, b = ml.split(list(range(100)), 0.2)
        self.assertEqual((len(a), len(b)), (80, 20))

    def test_ml_alone_cannot_accuse(self):
        # a URL with no rule hits must stay below the 'Suspicious' threshold
        r = scanner.scan_url("https://quiet-example.com/")
        if r["rule_score"] < 10:
            self.assertLess(r["score"], engine.SUSPICIOUS_AT)


class TestMessages(unittest.TestCase):
    def test_extract_urls(self):
        t = "Visit https://a.example.com/x, or www.b-site.top/y. Mail me at john@gmail.com"
        self.assertEqual(messages.extract_urls(t), ["https://a.example.com/x", "www.b-site.top/y"])

    def test_scam_message(self):
        m = messages.scan_message("Your SBI account will be blocked today. Update KYC now: http://sbi-kyc-update.xyz/login and share OTP")
        self.assertEqual(m["verdict"], "Likely Phishing")
        self.assertTrue(len(m["flags"]) >= 3)

    def test_normal_message(self):
        m = messages.scan_message("Hi! Meeting at 5pm, link: https://meet.google.com/abc-defg-hij")
        self.assertEqual(m["verdict"], "Looks Safe")

    def test_wording_only_scam(self):
        m = messages.scan_message("Urgent: your account will be blocked. Share your OTP to confirm. Do not tell anyone.")
        self.assertIn(m["verdict"], ("Suspicious", "Likely Phishing"))

    def test_empty(self):
        with self.assertRaises(ValueError):
            messages.scan_message("  ")


class TestRealWorld(unittest.TestCase):
    """Patterns seen in real phishing feeds and real genuine SMS."""

    def test_free_hosting_with_brand_lookalike(self):
        r = scanner.scan_url("https://paypa1-login.pages.dev/x")
        self.assertEqual(r["verdict"], "Likely Phishing")

    def test_steam_clone_with_heavy_typos(self):
        self.assertGreaterEqual(scanner.scan_url("https://steancomnmuntiy.com/proflies/765611979602699268")["score"], 25)

    def test_hacked_cms_path_is_noted(self):
        a = engine.analyze("https://some-small-shop.com/wp-includes/js/confirm/index.php")
        self.assertTrue(any("hacked" in r for r in a.reasons))

    def test_purchase_is_not_chase(self):
        self.assertEqual(engine.analyze("https://purchase-orders.example.com").features["brand_abuse"], 0)

    def test_genuine_messages_stay_safe(self):
        import samples
        for label, text in samples.MESSAGES:
            if label.startswith("GENUINE"):
                m = messages.scan_message(text)
                self.assertEqual(m["verdict"], "Looks Safe", f"{label}: {m['score']} {m['reasons']}")

    def test_scam_messages_are_flagged(self):
        import samples
        for label, text in samples.MESSAGES:
            if label.startswith("SCAM"):
                m = messages.scan_message(text)
                self.assertGreaterEqual(m["score"], 25, f"{label}: {m['score']}")

    def test_sample_links_scan_without_errors(self):
        import samples
        for u in samples.REAL_PHISHING + samples.REAL_LEGIT:
            scanner.scan_url(u)

    def test_genuine_sample_links_are_safe(self):
        import samples
        for u in samples.REAL_LEGIT:
            self.assertEqual(scanner.scan_url(u)["verdict"], "Looks Safe", u)

    def test_ml_ignores_path(self):
        model = scanner.get_model()
        if model:
            a = ml.predict(model, "https://example-site.com/a")
            b = ml.predict(model, "https://example-site.com/login/verify/account?x=1")
            self.assertAlmostEqual(a, b, places=9)


class TestStorageAndReport(unittest.TestCase):
    def test_history(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "h.db")
            storage.add_scan("url", "http://x.example", "Suspicious", 40, ["why"], path=db)
            storage.add_scan("url", "https://google.com", "Looks Safe", 0, [], path=db)
            self.assertEqual(len(storage.recent(path=db)), 2)
            self.assertEqual(storage.stats(path=db)["total"], 2)
            storage.clear(path=db)
            self.assertEqual(storage.stats(path=db)["total"], 0)

    def test_reports(self):
        results = [scanner.scan_url(u) for u in (LEGIT[0], PHISH[0])]
        with tempfile.TemporaryDirectory() as d:
            report.to_csv(results, os.path.join(d, "r.csv"))
            report.to_html(results, os.path.join(d, "r.html"))
            with open(os.path.join(d, "r.html"), encoding="utf-8") as f:
                self.assertIn("Likely Phishing", f.read())
            with open(os.path.join(d, "r.csv"), encoding="utf-8") as f:
                self.assertEqual(len(list(csv.reader(f))), 3)

    def test_html_escapes(self):
        r = scanner.scan_url("http://x.example.top/<script>alert(1)</script>")
        with tempfile.TemporaryDirectory() as d:
            report.to_html([r], os.path.join(d, "r.html"))
            with open(os.path.join(d, "r.html"), encoding="utf-8") as f:
                self.assertNotIn("<script>alert", f.read())


class TestDeepScanOffline(unittest.TestCase):
    def test_unresolvable_domain_does_not_crash(self):
        import netcheck
        out = netcheck.deep_scan("http://this-domain-should-not-exist-phishguard.invalid/")
        self.assertTrue(any("DNS" in r for _, r in out["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
