"""
PhishGuard Pro - SMS / WhatsApp / e-mail message scanner
========================================================
Finds every link in a pasted message, scans each one, and also looks for the
pressure tactics scammers use (urgency, KYC, OTP requests, fake prizes, fake
parcel fees, APK installs ...).
"""

import re

import engine
import scanner

_TLDS = ("com|in|net|org|xyz|top|tk|ml|ga|cf|gq|click|link|live|info|co|online|site|shop|club|"
         "icu|buzz|app|me|ly|gl|to|cc|ws|support|help|cyou|sbs|bid|work|loan|zip|page|cloud")
URL_RE = re.compile(
    r"(?i)(?:https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+|"
    r"\b(?:[a-z0-9][a-z0-9\-]*\.)+(?:" + _TLDS + r")\b(?:/[^\s<>\"')\]]*)?)"
)

# (regex, points, label)
CUES = [
    (r"\b(urgent|immediately|within \d+ ?(hours?|hrs|mins?|minutes)|expires? (today|soon)|last (chance|warning)|act now|final notice)\b",
     10, "Creates urgency / time pressure"),
    (r"\b(account|a/c|card|sim|number|upi|wallet|service|electricity|power|connection|supply|gas|water|policy)\b.{0,40}\b(block(ed)?|suspend(ed)?|deactivat\w+|freez\w+|clos(ed|ure)|expire[sd]?|disconnect\w*)\b",
     15, "Threatens to block / suspend an account or service"),
    (r"\b(kyc|pan (card|number|update)|aadhaar|aadhar|e-?kyc)\b",
     15, "Asks for KYC / PAN / Aadhaar details"),
    (r"(\b(otp|pin|cvv|password|passcode)\b.{0,40}\b(share|send|enter|confirm|verify|tell|provide)\b)|(\b(share|send|enter|confirm|verify|tell|provide)\b.{0,40}\b(otp|pin|cvv|password|passcode)\b)",
     25, "Asks for an OTP / PIN / CVV / password"),
    (r"\b(you (have )?won|winner|lottery|lucky draw|prize|reward points|cashback|gift card|free (gift|recharge|iphone|data))\b",
     15, "Promises a prize, reward or freebie"),
    (r"\b(refund|income tax|gst|electricity bill|power (will be )?disconnect\w*|bill (is )?(overdue|pending))\b",
     10, "Mentions a refund, tax or bill payment"),
    (r"\b(parcel|courier|package|customs|delivery)\b.{0,50}\b(fee|charge|pending|held|failed|undelivered)\b",
     15, "Claims a parcel needs a fee / is held"),
    (r"\b(click (here|the link|below)|tap (here|the link)|log ?in (here|now)|verify (now|here)|update (now|here))\b",
     10, "Pushes you to click a link"),
    (r"\b(install|download)\b.{0,25}\b(apk|app|application)\b",
     15, "Asks you to install an app / APK"),
    (r"\b(work from home|part[- ]time job|earn\b.{0,20}\b(daily|per day|per hour|weekly))\b",
     10, "Offers easy money / a fake job"),
    (r"\b(send|pay|transfer|deposit)\b.{0,30}(₹|rs\.?|inr)\s?\d",
     10, "Asks you to send money"),
    (r"\b(do not|don'?t) (tell|share|inform)\b",
     10, "Asks you to keep it secret"),
    (r"\b(contact|call|whatsapp|message|text)\b.{0,60}?(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)",
     15, "Asks you to contact a mobile number (typical of fake electricity / bank / courier officers)"),
    (r"\b(like|liking|subscribe|subscribing|rate|rating|review|reviewing)\b.{0,25}\b(videos?|youtube|products?|hotels?|reels?)\b",
     15, "Pays money for simple tasks (like / rate / review) - a common task scam"),
    (r"\b(whatsapp|telegram)\b.{0,40}\b(now|group|link|number|us)\b|\b(contact|message|join)\b.{0,25}\b(whatsapp|telegram)\b",
     10, "Moves you onto WhatsApp / Telegram"),
]
_CUES = [(re.compile(rx, re.I | re.S), pts, label) for rx, pts, label in CUES]


def extract_urls(text: str):
    """All links in the text, de-duplicated, in order of appearance."""
    seen, out = set(), []
    for m in URL_RE.finditer(text):
        before = text[m.start() - 1] if m.start() > 0 else " "
        if before in "@":                      # part of an e-mail address
            continue
        u = m.group(0).rstrip(".,;:!?)]'\"")
        if u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out


# Genuine banks, Google, delivery apps etc. WARN you: "Do not share this OTP with anyone".
# That sentence protects you, so it must not be counted as a scam signal.
SAFETY_WARNING = re.compile(
    r"\b(?:please |kindly )?(?:do not|don'?t|dont|never|not to)\s+(?:share|disclose|reveal|give|forward)\b[^.\n!]*", re.I)


def language_flags(text: str):
    cleaned = SAFETY_WARNING.sub(" ", text)
    return [(label, pts) for rx, pts, label in _CUES if rx.search(cleaned)]


def scan_message(text: str, deep: bool = False) -> dict:
    if not text or not text.strip():
        raise ValueError("Message is empty")
    results, errors = scanner.scan_many(extract_urls(text), deep=deep)
    flags = language_flags(text)
    lang = min(100, sum(p for _, p in flags))
    top = max((r["score"] for r in results), default=0)

    if results:
        score = min(100, round(0.75 * top + 0.6 * lang)) if lang else top
        score = max(score, top)
    else:
        score = min(60, lang)           # no link: language alone is only a warning
    verdict = engine.verdict_for(score)

    reasons = [f"{label}." for label, _ in flags]
    if results:
        worst = max(results, key=lambda r: r["score"])
        if worst["score"] >= engine.SUSPICIOUS_AT:
            reasons.insert(0, f"Link '{worst['url']}' is {worst['verdict'].lower()} ({worst['score']}/100).")
    elif flags:
        reasons.append("The message contains no link, but uses common scam wording.")
    if not reasons:
        reasons = ["No scam wording or suspicious links found."]

    return {"verdict": verdict, "score": int(score), "language_score": lang,
            "flags": flags, "links": results, "link_errors": errors, "reasons": reasons}
