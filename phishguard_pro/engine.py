"""
PhishGuard Pro - detection engine
=================================
Looks only at the TEXT of a URL (it never connects to the site) and produces:
  * a rule-based risk score (0-100) with human-readable reasons
  * a numeric feature dictionary that the machine-learning model also uses

Pure Python, standard library only.
"""

import ipaddress
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

# ----------------------------------------------------------------------
# Knowledge base
# ----------------------------------------------------------------------
# brand -> official domains (registered domains)
OFFICIAL = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "gmail.com", "youtube.com", "goo.gl", "gstatic.com"},
    "facebook": {"facebook.com", "fb.com", "fb.me"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amzn.in", "amzn.to", "amazonaws.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "bing.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbilife.co.in"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com", "icicidirect.com", "iciciprulife.com"},
    "axis": {"axisbank.com"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "irctc": {"irctc.co.in"},
    "flipkart": {"flipkart.com", "fkrt.it"},
    # brands that real phishing campaigns copy a lot (games, crypto, delivery, banks, telecom)
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com", "valvesoftware.com"},
    "roblox": {"roblox.com", "rbxcdn.com"},
    "discord": {"discord.com", "discord.gg", "discordapp.com"},
    "walletconnect": {"walletconnect.com", "walletconnect.org"},
    "metamask": {"metamask.io"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "trustwallet": {"trustwallet.com"},
    "opensea": {"opensea.io"},
    "usps": {"usps.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "citibank": {"citi.com", "citibank.com"},
    "yahoo": {"yahoo.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "ebay": {"ebay.com", "ebay.in"},
    "airtel": {"airtel.in", "airtel.com"},
    "jio": {"jio.com", "ril.com"},
    "indiapost": {"indiapost.gov.in"},
    "epfo": {"epfindia.gov.in"},
}
# extra words that identify a brand inside a domain
BRAND_ALIASES = {
    "sbi": ["onlinesbi", "sbicard"],
    "hdfc": ["hdfcbank"],
    "icici": ["icicibank"],
    "steam": ["steamcommunity", "steampowered"],
    "microsoft": ["office365"],
    "bankofamerica": ["bofa"],
}
# short or everyday-word brands: only an exact word counts ("purchase" must not match "chase")
STRICT_BRANDS = {"chase", "apple", "steam", "axis", "jio", "dhl", "ebay", "yahoo", "amazon", "google", "airtel"}

# other well-known safe sites (so we do not raise false alarms)
TRUSTED_EXTRA = {
    "wikipedia.org", "github.com", "python.org", "stackoverflow.com", "linkedin.com",
    "twitter.com", "x.com", "telegram.org", "zoho.com", "mozilla.org", "reddit.com",
    "bbc.com", "bbc.co.uk", "thehindu.com", "ndtv.com", "timesofindia.com",
    "indiatimes.com", "hindustantimes.com", "nptel.ac.in", "coursera.org", "udemy.com",
    "medium.com", "quora.com", "openai.com", "anthropic.com", "claude.ai",
    "adobe.com", "dropbox.com", "zoom.us", "swiggy.com", "zomato.com", "myntra.com",
    "uidai.gov.in", "incometax.gov.in", "india.gov.in", "digilocker.gov.in",
}
TRUSTED_SUFFIXES = (".gov.in", ".nic.in", ".ac.in", ".edu", ".gov", ".mil")

# sites where ANYONE can host content, so the brand name alone proves nothing
USER_CONTENT_HOSTS = {
    "docs.google.com", "forms.gle", "sites.google.com", "drive.google.com",
    "storage.googleapis.com", "onedrive.live.com",
}
USER_CONTENT_REGS = {
    "amazonaws.com", "dropbox.com", "sharepoint.com", "blogspot.com",
    "googleusercontent.com", "forms.gle",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "password", "banking", "wallet", "billing", "suspend", "unlock", "otp",
    "kyc", "refund", "reward", "claim", "alert", "authenticate",
    "recover", "restore", "validate", "webmail", "walletconnect", "helpdesk", "login_submit",
]
# weaker words: common on honest sites too, so they count for less
WEAK_KEYWORDS = [
    "support", "service", "member", "portal", "connect", "gift", "bonus", "free",
    "payment", "invoice", "delivery", "tracking", "security", "customer", "official",
    "invite", "tradeoffer", "tradoffer",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "bl.ink", "pxlme.me",
}

RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "work", "loan",
    "icu", "buzz", "cyou", "monster", "sbs", "rest", "bid", "cam", "men", "date",
    "link", "country", "stream", "download", "mov",
}
# cheap TLDs that are abused a lot but also used by honest sites -> smaller penalty
WEAK_RISKY_TLDS = {
    "club", "online", "site", "shop", "live", "store", "space", "website", "fun",
    "vip", "bond", "cfd", "quest", "lol", "pw", "ws", "cc", "tech", "life", "today",
}

# free hosting / website builders / tunnels / dynamic DNS: anyone can publish a page here
FREE_HOSTING = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "web.app", "firebaseapp.com",
    "pages.dev", "workers.dev", "netlify.app", "github.io", "glitch.me",
    "herokuapp.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "duckdns.org", "blogspot.com", "vercel.app", "onrender.com", "repl.co",
    "r2.dev", "gitbook.io", "webflow.io", "mybluehost.me", "my.id", "bitbucket.io",
    "godaddysites.com", "square.site", "filesusr.com", "ddns.net", "no-ip.org",
    "hopto.org", "zapto.org", "serveo.net", "loca.lt", "webwave.dev", "pxlme.me",
    "myshopify.com", "wordpress.com", "sites.google.com", "framer.website", "framer.app",
    "surge.sh", "fly.dev", "railway.app", "replit.app", "teachable.com", "carrd.co",
    "webcindario.com", "yolasite.com", "jimdofree.com", "wuaze.com", "infinityfreeapp.com",
    "rf.gd", "epizy.com", "000webhost.com", "ukit.me", "tripod.com", "pagedemo.co",
    "swtest.ru", "bravesites.com", "strikingly.com", "mystrikingly.com", "typedream.app",
}
FREE_HOST_LABELS = {"blogspot"}      # blogspot.com, blogspot.fi, blogspot.sn ...

TWO_PART_SUFFIXES = {
    "co.in", "org.in", "net.in", "gov.in", "nic.in", "ac.in", "res.in", "edu.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.jp", "com.br", "co.za",
    "com.sg", "com.pk", "com.bd", "co.nz",
}

DANGEROUS_EXT = re.compile(r"\.(apk|exe|scr|bat|cmd|msi|vbs|jar|iso|dmg)(?:$|[?#])", re.I)
ARCHIVE_EXT = re.compile(r"\.(zip|rar|7z)(?:$|[?#])", re.I)

# characters attackers swap to imitate letters
_CONFUSABLES = {
    "0": "o", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a", "|": "l",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ɡ": "g", "ο": "o", "ν": "v", "α": "a",
}
_CONF_TABLE = str.maketrans(_CONFUSABLES)

SUSPICIOUS_AT = 25
PHISHING_AT = 55

# order matters: the ML model uses this exact list
FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len", "dots_host", "hyphens_host",
    "digits_host", "digit_ratio", "subdomains", "is_ip", "has_at", "is_https",
    "nonstd_port", "special_chars", "n_params", "entropy_host", "entropy_path",
    "kw_count", "path_depth", "risky_tld", "shortener", "nonascii_host",
    "brand_abuse", "typosquat", "free_host", "dangerous_ext", "trusted",
]


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    """Number of single-character edits needed to turn a into b."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def entropy(s: str) -> float:
    """Shannon entropy: random-looking strings score high."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_obfuscated_ip(host: str) -> bool:
    """0x7f000001 or 2130706433 style addresses."""
    return bool(re.fullmatch(r"0x[0-9a-f]+", host) or re.fullmatch(r"\d{8,10}", host))


def registered_domain(host: str) -> str:
    """login.paypal.com -> paypal.com ; www.sbi.co.in -> sbi.co.in"""
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _confusable_variants(label: str):
    """Normalised spellings a look-alike label could be imitating."""
    base = unicodedata.normalize("NFKC", label).lower()
    out = set()
    for one in ("l", "i"):                       # the digit 1 can mean l or i
        s = base.translate(_CONF_TABLE).replace("1", one)
        out.add(s)
        out.add(s.replace("rn", "m").replace("vv", "w"))
    return out


def verdict_for(score: float) -> str:
    if score >= PHISHING_AT:
        return "Likely Phishing"
    if score >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Looks Safe"


# ----------------------------------------------------------------------
# URL parsing
# ----------------------------------------------------------------------
@dataclass
class ParsedURL:
    raw: str
    scheme: str            # "" when the user typed no scheme
    host: str
    port: int
    path: str
    query: str
    has_userinfo: bool
    reg: str
    label: str
    tld: str


def parse_url(url: str) -> ParsedURL:
    raw = (url or "").strip()
    if not raw:
        raise ValueError("Empty URL")
    if re.search(r"\s", raw):
        raise ValueError("URL must not contain spaces")
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", raw))
    try:
        p = urlparse(raw if has_scheme else "http://" + raw)
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port or 0
    except ValueError:
        raise ValueError(f"Invalid URL: {raw}")
    if not host:
        raise ValueError(f"Invalid URL (no host found): {raw}")
    reg = registered_domain(host)
    return ParsedURL(
        raw=raw,
        scheme=p.scheme.lower() if has_scheme else "",
        host=host,
        port=port,
        path=p.path or "",
        query=p.query or "",
        has_userinfo="@" in p.netloc,
        reg=reg,
        label=reg.split(".")[0],
        tld=host.rsplit(".", 1)[-1],
    )


# ----------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------
@dataclass
class Analysis:
    parsed: ParsedURL
    features: dict
    findings: list = field(default_factory=list)   # (points, reason)
    trusted: bool = False

    @property
    def rule_score(self) -> int:
        return min(100, sum(p for p, _ in self.findings))

    @property
    def reasons(self) -> list:
        return [r for _, r in sorted(self.findings, key=lambda f: -f[0])]


def _is_trusted(parsed: ParsedURL) -> bool:
    if parsed.host in USER_CONTENT_HOSTS or parsed.reg in USER_CONTENT_REGS:
        return False
    if parsed.reg in TRUSTED_EXTRA:
        return True
    if any(parsed.reg in d for d in OFFICIAL.values()):
        return True
    return parsed.reg.endswith(TRUSTED_SUFFIXES)


def analyze(url: str) -> Analysis:
    p = parse_url(url)
    host, reg = p.host, p.reg
    lowered = (p.host + p.path + "?" + p.query).lower()
    ip = is_ip(host)
    obf_ip = is_obfuscated_ip(host)
    trusted = _is_trusted(p)
    user_content = p.host in USER_CONTENT_HOSTS or reg in USER_CONTENT_REGS

    findings = []
    add = lambda pts, why: findings.append((pts, why))

    # ---- structure ---------------------------------------------------
    if ip:
        add(35, "Uses an IP address instead of a domain name.")
    if obf_ip:
        add(35, "Uses a disguised numeric IP address (hex or decimal form).")
    if p.has_userinfo:
        add(25, "Contains '@' before the host, which can hide the real destination.")
    if len(p.raw) > 100:
        add(15, f"Unusually long URL ({len(p.raw)} characters).")
    elif len(p.raw) > 75:
        add(8, f"Fairly long URL ({len(p.raw)} characters).")

    subs = 0 if ip else len(host.split(".")) - len(reg.split("."))
    if subs >= 3:
        add(15, f"Too many subdomains ({subs}), a common disguise trick.")
    if host.replace("xn--", "").count("-") >= 2:
        add(10, "Many hyphens in the domain name (misleading domain pattern).")
    if p.scheme == "http":
        add(10, "Uses HTTP, not HTTPS (connection is not encrypted).")
    if p.port and p.port not in (80, 443):
        add(10, f"Non-standard port ({p.port}).")
    if "//" in p.path:
        add(10, "Double slash inside the path (possible redirect trick).")
    if lowered.count("%") >= 3:
        add(5, "Heavy percent-encoding in the URL.")

    # ---- domain reputation hints ------------------------------------
    if not ip and p.tld in RISKY_TLDS:
        add(15, f"Uses a TLD often abused for scams (.{p.tld}).")
    elif not ip and p.tld in WEAK_RISKY_TLDS:
        add(8, f"Uses a cheap TLD that is frequently abused (.{p.tld}).")
    if reg in URL_SHORTENERS:
        add(25, "URL shortener hides the real destination (cannot tell where it leads).")
    free_host = reg in FREE_HOSTING or reg.split(".")[0] in FREE_HOST_LABELS
    if free_host and host != reg:
        add(20, f"Hosted on a free hosting / website-builder / tunnel service ({reg}), the most common home of today's phishing pages.")
    if user_content and reg not in FREE_HOSTING:
        add(10, f"Hosted on a user-content service ({host}); the page owner is not the brand.")

    nonascii = any(ord(c) > 127 for c in host)
    if "xn--" in host or nonascii:
        add(25, "Domain uses punycode / non-English characters (may be a look-alike).")

    ent_host = entropy(p.label)
    digits_host = sum(c.isdigit() for c in host)
    alnum = p.label if "-" not in p.label else ""
    vowels = sum(c in "aeiou" for c in alnum) / max(len(alnum), 1)
    if (not ip and not obf_ip and len(alnum) >= 10 and ent_host > 3.2
            and (vowels < 0.25 or (any(c.isdigit() for c in alnum) and any(c.isalpha() for c in alnum)))):
        add(10, "Domain name looks random / auto-generated.")
    if not ip and not obf_ip and digits_host >= 4:
        add(10, "Domain contains many digits.")

    # ---- brand impersonation ----------------------------------------
    typosquat = 0
    brand_abuse = 0
    if not trusted and not ip:
        tokens = [t for t in re.split(r"[.\-_]", host) if t]
        # spellings to test for look-alikes: the whole label and each hyphen-separated piece
        sub_labels = host[: -len(reg)].rstrip(".").split(".") if host != reg else []
        pieces = {p.label} | {t for t in p.label.split("-") if len(t) >= 4}
        for sl in sub_labels:                      # paypa1-login.pages.dev -> also test 'paypa1'
            if len(sl) >= 4 and sl != "www":
                pieces.add(sl)
                pieces |= {t for t in sl.split("-") if len(t) >= 4}
        variant_sets = {pc: _confusable_variants(pc) for pc in pieces}
        for brand, domains in OFFICIAL.items():
            if reg in domains:
                continue
            names = {brand, *BRAND_ALIASES.get(brand, [])}
            # 1) look-alike spelling of the brand (paypa1, g00gle, arnazon, steanconnmuity)
            hit = None
            for name in sorted(names, key=len, reverse=True):
                for pc, variants in variant_sets.items():
                    if pc != name and any(v == name for v in variants):
                        hit = (40, f"Look-alike of '{brand}': '{pc}' swaps characters to imitate '{name}'.")
                        break
                    if len(name) >= 5:
                        limit = 1 if len(name) <= 7 else (2 if len(name) <= 11 else (3 if len(name) <= 12 else 4))
                        best = min(levenshtein(v, name) for v in variants)
                        if 0 < best <= limit and abs(len(pc) - len(name)) <= limit:
                            hit = (35, f"'{pc}' is a near-copy of '{name}' (possible typosquatting of {brand}).")
                            break
                if hit:
                    break
            if hit:
                add(*hit)
                typosquat = 1
                break
            # 2) brand name used inside somebody else's domain
            def mentions(t):
                for n in names:
                    if t == n:
                        return True
                    if len(n) >= 5 and n not in STRICT_BRANDS and n in t:
                        return True
                return False
            if any(mentions(t) for t in tokens):
                add(30, f"Mentions '{brand}' but '{reg}' is not a known official {brand} domain.")
                brand_abuse = 1
                break
        if not (typosquat or brand_abuse):
            path_l = p.path.lower()
            for brand in OFFICIAL:
                if len(brand) >= 4 and brand in path_l:
                    add(10, f"Brand name '{brand}' appears in the path of an unrelated domain.")
                    brand_abuse = 1
                    break

    # ---- content hints -----------------------------------------------
    if not trusted:
        hits = [k for k in SUSPICIOUS_KEYWORDS if k in lowered]
        weak = [k for k in WEAK_KEYWORDS if k in lowered and k not in " ".join(hits)]
        pts = min(8 * len(hits) + 3 * len(weak), 24)
        if pts:
            add(pts, "Suspicious keywords: " + ", ".join(hits + weak) + ".")
        pl = p.path.lower()
        if any(m in pl for m in ("/wp-content/", "/wp-includes/", "/wp-admin/", "/administrator/", "/components/com_", "/cgi-bin/", "/webscr")):
            add(10, "Path looks like a hacked website folder (WordPress/Joomla/cgi-bin), a favourite place to hide phishing pages.")
        if re.search(r"/[A-Za-z0-9+=_\-]{24,}(?:/|$|\?)", p.path):
            add(6, "Long random-looking token in the path.")
        if "/~" in p.path:
            add(6, "Personal-folder path (/~user) on an unrelated host.")
        qs = parse_qs(p.query)
        if any(v and re.match(r"https?(://|%3a)", v[0], re.I) for k, v in qs.items()
               if k.lower() in ("url", "redirect", "redirect_uri", "next", "goto", "link", "return", "continue")):
            add(10, "Query contains a redirect to another website (open-redirect pattern).")
    if DANGEROUS_EXT.search(p.path + ("?" + p.query if p.query else "")):
        add(20, "Link points to an installable/executable file (.apk, .exe ...).")
    elif ARCHIVE_EXT.search(p.path):
        add(8, "Link points to a compressed archive download.")

    # ---- trusted domains cap the score -------------------------------
    if trusted:
        findings = [(min(pts, 2), why) for pts, why in findings if pts and why.startswith("Uses HTTP")]
        findings.append((0, f"'{reg}' is a well-known trusted domain."))

    path_depth = len([s for s in p.path.split("/") if s])
    feats = {
        "url_len": len(p.raw), "host_len": len(host), "path_len": len(p.path),
        "query_len": len(p.query), "dots_host": host.count("."),
        "hyphens_host": host.replace("xn--", "").count("-"), "digits_host": digits_host,
        "digit_ratio": digits_host / max(len(host), 1), "subdomains": max(subs, 0),
        "is_ip": int(ip or obf_ip), "has_at": int(p.has_userinfo),
        "is_https": int(p.scheme == "https"), "nonstd_port": int(bool(p.port and p.port not in (80, 443))),
        "special_chars": sum(p.raw.count(c) for c in "?&=%_~#;$!*,"),
        "n_params": len(p.query.split("&")) if p.query else 0,
        "entropy_host": ent_host, "entropy_path": entropy(p.path.lower()),
        "kw_count": sum(k in lowered for k in SUSPICIOUS_KEYWORDS), "path_depth": path_depth,
        "risky_tld": int(p.tld in RISKY_TLDS or p.tld in WEAK_RISKY_TLDS), "shortener": int(reg in URL_SHORTENERS),
        "nonascii_host": int("xn--" in host or nonascii), "brand_abuse": brand_abuse,
        "typosquat": typosquat, "free_host": int(free_host), "dangerous_ext": int(bool(DANGEROUS_EXT.search(p.path))),
        "trusted": int(trusted),
    }
    return Analysis(parsed=p, features=feats, findings=findings, trusted=trusted)
