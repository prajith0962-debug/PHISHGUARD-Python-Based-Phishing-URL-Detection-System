"""
Examples for the drop-down lists in the app.

REAL_PHISHING : links taken from a public phishing feed (the open-source Phishing.Database
                project).  A random pick - the tool catches most, not all, and some of these
                pages may already be taken down.  They are only ever analysed as TEXT.
                NEVER open them in a browser.
REAL_LEGIT    : genuine links of well-known services.
MESSAGES      : typical scam SMS / WhatsApp messages reported by Indian cyber-crime
                authorities, and genuine messages from banks, Google, delivery apps, etc.
                (The scam links use made-up domains.)
"""

REAL_PHISHING = [
    "https://core-docs-8e33.alaonsresmiek.workers.dev/f186391b-52e8-4952-9437-a53b4470c399",
    "http://service-106787.weeblysite.com",
    "http://10056425-896521ntfcations.duckdns.org/failure.php?section_id=1-howtocontactmeta",
    "https://stepnconnectactivation.pages.dev/walletconnect",
    "https://walletconnect-explorer.pages.dev/zkgap",
    "http://100-americaamazon-900.com/amazon/cfcc5/wallet.php",
    "http://firstnigerianews.icu/secure05b.chase.com/web/auth/overviewaccounts/secure03b.chase.com/webhome/dm3ztu=",
    "http://111.90.142.27/banks/simplii",
    "https://steeamcommnity.com/105438932059",
    "https://liceosanroque.cl/huntington.com-web-app-cleint-help-login/huntington/mztmwzdk=",
    "https://lieferung-paket-kundin.belightful.co/delivery/checkout/receive/4381602",
    "https://qazalipbi.kz/wp-includes/ixr/index-121-90.html",
    "https://ms-yamaha.com/wp-admin/spotify",
]

REAL_LEGIT = [
    "https://www.irctc.co.in/nget/train-search",
    "https://retail.onlinesbi.sbi/retail/login.htm",
    "https://netbanking.hdfcbank.com/netbanking/",
    "https://accounts.google.com/signin/v2/identifier?service=mail",
    "https://www.amazon.in/gp/css/order-history?ref_=nav_AccountFlyout_orders",
    "https://www.paypal.com/signin",
    "https://www.incometax.gov.in/iec/foportal/",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://github.com/python/cpython/pull/100123",
    "https://docs.google.com/forms/d/e/1FAIpQLSdAbCdEfGhIjKlMnOp/viewform",
]

MESSAGES = [
    ("SCAM: SBI YONO KYC",
     "Dear SBI user, your YONO account will be blocked today. Update your KYC immediately: "
     "http://sbi-yono-kyc.xyz/update and share OTP to confirm."),
    ("SCAM: Electricity disconnection",
     "Dear customer, your electricity power will be disconnected tonight at 9.30pm because previous "
     "month bill was not updated. Contact electricity officer 9876543210 immediately."),
    ("SCAM: India Post parcel fee",
     "India Post: Your parcel is held at the warehouse due to incomplete address. Pay Rs.25 "
     "redelivery fee: http://indiapost-redelivery.top/track"),
    ("SCAM: Income tax refund",
     "Income Tax Dept: You have a pending refund of Rs.15,490. Claim now: "
     "http://incometax-refund-claim.click/pan-verify else it will expire."),
    ("SCAM: UPI cashback",
     "Congratulations! You won cashback of Rs.5000 on PhonePe. Click here to claim: "
     "http://phonepe-reward.icu/claim and enter your UPI PIN."),
    ("SCAM: Work-from-home task job",
     "Hi, part time job offer. Work from home, earn Rs.3000 daily just by liking videos. "
     "Contact us on WhatsApp now. Do not tell anyone."),
    ("SCAM: Fake rewards APK",
     "Your SBI rewards points worth Rs.9800 expire today. Download SBI Rewards app: "
     "http://sbirewards-app.top/sbi-rewards.apk"),
    ("SCAM: Credit card verification",
     "Your HDFC credit card is suspended. Verify now by sharing your card number and CVV: "
     "https://hdfc-card-verify.top/login"),
    ("SCAM: FASTag KYC",
     "Your FASTag KYC is incomplete and your account will be deactivated. Update now: "
     "http://fastag-kyc-update.top/verify"),
    ("SCAM: Free iPhone lucky draw",
     "Amazon: You have been selected for a free iPhone 15 lucky draw. Claim your gift card "
     "within 24 hours: https://amazon-lucky-draw.click/claim"),
    ("GENUINE: Bank OTP",
     "123456 is your OTP for transaction of Rs.2,499.00 at AMAZON on your SBI Card ending 4821. "
     "Do not share this OTP with anyone. If not you, call 1800 1234. -SBI Card"),
    ("GENUINE: Google verification code",
     "G-482913 is your Google verification code. Do not share it with anyone."),
    ("GENUINE: Amazon delivery",
     "Your Amazon order will be delivered today. Share OTP 5821 with the delivery agent only at the "
     "time of delivery. Track: https://www.amazon.in/gp/your-account/order-details"),
    ("GENUINE: UPI debit alert",
     "Rs.1,500.00 debited from A/c XX1234 on 15-10-26 to VPA friend@okhdfcbank. Not you? "
     "Call 1800-202-6161 to block UPI. -HDFC Bank"),
    ("GENUINE: Electricity bill",
     "Dear consumer, your electricity bill of Rs.1,245 for Oct 2026 is generated. Due date 25-Oct. "
     "Pay at https://www.tnebnet.org or the TANGEDCO app."),
    ("GENUINE: IRCTC ticket",
     "PNR 4512345678: Your ticket is CONFIRMED. Train 12631 NELLAI EXP, 20-Oct. "
     "Have a safe journey. -IRCTC"),
    ("GENUINE: College notice",
     "Dear students, the internal exam timetable is published on the college website: "
     "https://www.annauniv.edu. Kindly check and report any mismatch by tomorrow."),
]
