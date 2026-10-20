import re

from .security_layers import SHORTENERS
from .url_utils import registered_domain

MAX_MESSAGE_LENGTH = 3000

SUSPICIOUS_CUTOFF = 35
FRAUD_CUTOFF = 70


SENSITIVE_TERMS = {
    "OTP": [
        "otp",
        "one time password",
        "one-time password",
        "verification code",
    ],
    "UPI PIN": [
        "upi pin",
        "upi-pin",
    ],
    "PIN": [
        "atm pin",
        "card pin",
        "debit card pin",
        "credit card pin",
    ],
    "CVV": [
        "cvv",
        "cvc",
    ],
    "Password": [
        "password",
        "banking password",
        "netbanking password",
    ],
    "Card details": [
        "card number",
        "debit card number",
        "credit card number",
        "expiry date",
    ],
    "Aadhaar/PAN": [
        "aadhaar number",
        "aadhar number",
        "pan number",
        "pan card",
    ],
}


# asking the user to hand over something
DISCLOSURE_WORDS = [
    "share",
    "send",
    "tell",
    "provide",
    "forward",
    "reply",
    "give",
    "disclose",
    "batao",
    "bataiye",
    "bhejo",
    "bhejiye",
    "dijiye",
]

# normal OTP sms also use these words, so they are weaker
WEAK_REQUEST_WORDS = [
    "enter",
    "submit",
    "confirm",
    "verify",
    "update",
]

REQUEST_WORDS = DISCLOSURE_WORDS + WEAK_REQUEST_WORDS


BRANDS = [
    "sbi",
    "state bank",
    "hdfc",
    "icici",
    "axis bank",
    "pnb",
    "bank of india",
    "bank of baroda",
    "paytm",
    "phonepe",
    "google pay",
    "gpay",
    "rbi",
    "npci",
]


SHORT_PATTERN = "|".join(re.escape(domain) for domain in SHORTENERS)

URL_PATTERN = re.compile(
    r"(https?://[^\s]+|www\.[^\s]+|"
    rf"\b(?:{SHORT_PATTERN})(?=[/\s.,;:!?)]|$)(?:/[^\s]*)?|"
    r"(?:[a-zA-Z0-9-]+\.)+"
    r"(?:com|in|org|net|co|xyz|top|click|link|site|online|info|shop|live|app|dev)\b"
    r"(?:/[^\s]*)?)",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(r"(?:\+91[\s-]?)?\b[6-9]\d{9}\b|\b1[89]00[\s-]?\d{3}[\s-]?\d{3,4}\b")


SAFE_OTP_PATTERNS = [
    r"\bnever\s+share\s+(?:your\s+|this\s+)?otp\b",
    r"\bdo not\s+share\s+(?:your\s+|this\s+)?otp\b",
    r"\bdon't\s+share\s+(?:your\s+|this\s+)?otp\b",
    r"\bdont\s+share\s+(?:your\s+|this\s+)?otp\b",
    r"\bnever\s+disclose\s+(?:your\s+|this\s+)?otp\b",
    r"\bdo not\s+disclose\s+(?:your\s+|this\s+)?otp\b",
    r"\bdo not\s+share\s+(?:it|this)\b",
    r"\bbank\s+will\s+never\s+ask.{0,40}?\botp\b",
    r"\botp\b.{0,30}\bkisi ko (?:bhi )?(?:na|mat)\b",
]

# message that is just giving an OTP, like "Your OTP is 458921"
OTP_DELIVERY_PATTERNS = [
    r"\b(?:otp|verification code|one[- ]time password)\b\D{0,25}\b\d{4,8}\b",
    r"\b\d{4,8}\b\D{0,25}\b(?:otp|verification code|one[- ]time password)\b",
]


# Each scam type: (signal name, points, reason shown to the user, patterns).
# Points were set by hand and checked on tests/data/sample_messages.csv.
SCAM_PATTERNS = [
    (
        "urgency",
        15,
        "Message creates urgency or pressure",
        [
            r"\burgent(?:ly)?\b",
            r"\bimmediately\b",
            r"\bright now\b",
            r"\bact now\b",
            r"\bwithin \d+ (?:hours?|hrs|minutes?|mins)\b",
            r"\btoday itself\b",
            r"\b(?:update|verify|pay|call|login|click)\s+(?:\w+\s+){0,2}now\b",
            r"\bturant\b",
            r"\bjaldi\b",
            r"\babhi\b",
        ],
    ),
    (
        "account_threat",
        20,
        "Account, KYC, card, or SIM blocking threat detected",
        [
            r"account.{0,80}(?:blocked|suspended|frozen|closed|deactivated)",
            r"kyc.{0,80}(?:expired|pending|blocked|required|update|incomplete)",
            r"(?:card|sim|pan).{0,80}(?:blocked|deactivated|suspended)",
            r"(?:account|khata|card|sim).{0,40}(?:band|block)\s+ho",
        ],
    ),
    (
        "reward_bait",
        35,
        "Lottery, prize, or reward bait detected",
        [
            r"(?:lottery|lucky draw|kbc|kaun banega|jackpot).{0,80}(?:won|winner|prize|lakh|crore|\brs\b|₹|claim)",
            r"\b(?:won|win|winner|jeeta|jeete)\b.{0,80}(?:prize|lottery|lakh|crore|car|iphone|inaam)",
            r"(?:cashback|reward|prize|inaam).{0,80}(?:claim|receive|pending|collect)",
            # "refund will be credited" is a normal message, so only count
            # a refund that asks you to do something
            r"refund.{0,80}(?:claim|collect|click|install|share|submit|enter)",
        ],
    ),
    (
        "qr_to_receive",
        40,
        "Asks you to scan a QR or enter a PIN to receive money (you never need to)",
        [
            r"scan.{0,40}\bqr\b.{0,60}(?:receive|get|credited|refund|cashback)",
            r"(?:receive|get).{0,60}(?:scan.{0,20}\bqr\b|enter.{0,20}upi pin)",
        ],
    ),
    (
        "remote_access",
        35,
        "Remote access or suspicious app installation requested",
        [
            r"(?:anydesk|teamviewer|quicksupport|quick support|rustdesk|remote access|screen ?share)",
            r"install.{0,40}(?:app|apk).{0,40}(?:support|verify|kyc|refund|update)",
            r"\.apk\b",
        ],
    ),
    (
        "payment_request",
        18,
        "Payment or UPI request detected",
        [
            r"(?:pay|transfer|send|bhejo|bhej do).{0,60}(?:\brs\b\.?|inr|₹|rupee|paise)",
            r"upi\s+(?:collect|request)",
            r"scan\s+(?:this\s+|the\s+)?qr",
            r"(?:processing|registration|security|delivery|customs)\s+(?:fee|charge|deposit)",
        ],
    ),
    (
        "family_emergency",
        35,
        "Family emergency story asking for money",
        [
            r"(?:hospital|accident|emergency|police station|stuck|arrested).{0,120}(?:send|transfer|bhej|paise|money|\brs\b|₹|\bpay\b)",
            r"(?:send|transfer|bhej|paise|money).{0,120}(?:hospital|accident|emergency|police station)",
            r"(?:this is my new number|mera naya number|new number hai|changed my number).{0,160}(?:send|transfer|bhej|paise|money|pay|urgent)",
        ],
    ),
    (
        "utility_disconnection",
        35,
        "Electricity, gas, or phone disconnection threat",
        [
            r"(?:electricity|bijli|power|light|gas|connection|sim)\b.{0,80}(?:disconnect\w*|will be cut|kat jayega|kat diya|band ho jayega|band kar)",
            r"(?:disconnect\w*).{0,80}(?:tonight|today|aaj raat|9:30|10:30|call)",
        ],
    ),
    (
        "parcel_scam",
        30,
        "Parcel or customs problem used as bait",
        [
            r"(?:parcel|courier|package|shipment|consignment|fedex|dhl|blue ?dart).{0,80}(?:held|seized|on hold|customs|illegal|drugs|undeliver|failed|incomplete address|address (?:issue|problem|update))",
        ],
    ),
    (
        "authority_threat",
        40,
        "Fake police, CBI, customs, or 'digital arrest' threat",
        [
            r"digital arrest",
            r"(?:cbi|ed officer|enforcement directorate|narcotics|ncb|cyber ?crime|police|trai|customs|income tax).{0,100}(?:arrest|warrant|case (?:registered|filed)|\bfir\b|legal action|investigation|money laundering|suspend)",
            r"(?:arrest|warrant).{0,60}(?:against you|in your name|aapke naam)",
            r"(?:illegal|drugs|narcotics).{0,60}(?:found|seized|in your (?:parcel|package|name))",
        ],
    ),
    (
        "job_task_scam",
        35,
        "Too-good-to-be-true job or online task offer",
        [
            r"(?:part[- ]time|work from home|ghar baithe|home based)\b.{0,100}(?:earn|income|salary|kamaye|kamao|\brs\b|₹|daily|per day)",
            r"(?:earn|kamaye|kamao)\s+(?:rs\.?\s*|₹\s*)?\d[\d,]*.{0,40}(?:daily|per day|roz|a day|weekly)",
            r"(?:like|subscribe|rate)\s+(?:youtube\s+)?(?:videos?|hotels?|products?|reviews?).{0,80}(?:earn|paid|\brs\b|₹|income)",
            r"(?:prepaid|telegram)\s+tasks?",
            r"earning opportunit",
        ],
    ),
    (
        "investment_scam",
        35,
        "Unrealistic investment or trading profit promise",
        [
            r"double (?:your )?(?:money|investment|amount)",
            r"guaranteed\s+(?:return|profit|income)",
            r"\d+\s?%\s+(?:daily|weekly|monthly|per day|per week)\s+(?:return|profit)",
            r"(?:crypto|bitcoin|forex|stock|share market|ipo).{0,60}(?:guaranteed|sure shot|100%|vip group|tips group|profit daily)",
        ],
    ),
    (
        "loan_offer",
        20,
        "Instant loan offer that asks for a fee or app install",
        [
            r"(?:instant|pre-?approved|guaranteed)\s+(?:personal\s+)?loan.{0,120}(?:fee|charge|deposit|install|download|apk|link|click)",
            r"loan.{0,40}(?:approved|sanctioned).{0,80}(?:fee|charge|deposit|pay)",
        ],
    ),
    (
        "move_to_chat",
        10,
        "Asks you to continue on WhatsApp or Telegram",
        [
            r"(?:whatsapp|telegram)\s+(?:me|us|karo|kare|kijiye|on|par|pe)\b",
            r"(?:contact|message|text|join)\s+(?:us\s+|me\s+)?(?:on|at|via)\s+(?:whatsapp|telegram)",
            r"\bt\.me/",
            r"wa\.me/",
        ],
    ),
]


def extract_urls(message):
    urls = []

    for url in URL_PATTERN.findall(message):
        url = url.rstrip(".,);]}!?")

        if not url.lower().startswith(("http://", "https://")):
            url = "https://" + url

        if url not in urls:
            urls.append(url)

    return urls


def has_pattern(text, patterns):
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


def request_near_term(text, term, words):
    word_pattern = "|".join(re.escape(word) for word in words)
    term_pattern = re.escape(term)

    before = (
        rf"\b(?:{word_pattern})\b"
        rf"(?:\s+\w+){{0,4}}\s+"
        rf"{term_pattern}\b"
    )

    after = (
        rf"\b{term_pattern}\b"
        rf"(?:\s+\w+){{0,4}}\s+"
        rf"\b(?:{word_pattern})\b"
    )

    return bool(
        re.search(before, text, re.IGNORECASE)
        or re.search(after, text, re.IGNORECASE)
    )


def remove_safe_otp_warnings(text):
    for pattern in SAFE_OTP_PATTERNS:
        text = re.sub(pattern, "", text, flags=re.IGNORECASE)

    return text


def get_requested_items(text, words):
    items = []

    for name, terms in SENSITIVE_TERMS.items():
        for term in terms:
            if request_near_term(text, term, words):
                items.append(name)
                break

    return items


def asks_to_disclose(text, items):
    for item in items:
        for term in SENSITIVE_TERMS[item]:
            if request_near_term(text, term, DISCLOSURE_WORDS):
                return True

    return False


def has_brand(text):
    for brand in BRANDS:
        if re.search(rf"\b{re.escape(brand)}\b", text):
            return True

    return False


def is_shortened(url):
    try:
        hostname = url.split("//", 1)[-1].split("/", 1)[0].lower()
    except IndexError:
        return False

    return registered_domain(hostname) in SHORTENERS


def message_status(score):
    if score >= FRAUD_CUTOFF:
        return "Likely Fraud"

    if score >= SUSPICIOUS_CUTOFF:
        return "Suspicious"

    return "Low Risk"


def analyze_scam_message(message, url_predictor=None):
    """Score a message with readable rules.

    url_predictor, if given, is called for each link (up to 5) and must
    return (result, risk_score, reasons), like predict.predict_url.
    """
    message = str(message).strip()

    if not message:
        raise ValueError("Message cannot be empty.")

    message = message[:MAX_MESSAGE_LENGTH]
    text = " ".join(message.lower().split())

    score = 0
    reasons = []
    signals = []

    urls = extract_urls(message)

    safe_otp_warning = has_pattern(text, SAFE_OTP_PATTERNS)
    otp_delivery = has_pattern(text, OTP_DELIVERY_PATTERNS)

    request_text = remove_safe_otp_warnings(text)

    # a plain "your OTP is 123456, use it to verify" sms (no link)
    # should not count weak words like verify/enter as a request
    if otp_delivery and not urls:
        request_words = DISCLOSURE_WORDS
    else:
        request_words = REQUEST_WORDS

    requested_items = get_requested_items(request_text, request_words)

    if requested_items:
        items = ", ".join(requested_items)

        if asks_to_disclose(request_text, requested_items):
            score += 55
            reasons.append(f"Message asks you to share sensitive information: {items}")
            signals.append("credential_disclosure")
        else:
            score += 35
            reasons.append(f"Message asks for sensitive information: {items}")
            signals.append("credential_request")

    for signal, points, reason, patterns in SCAM_PATTERNS:
        if has_pattern(text, patterns):
            score += points
            reasons.append(reason)
            signals.append(signal)

    phone_numbers = PHONE_PATTERN.findall(message)

    # a phone number alone is normal, only count it next to a scam story
    if phone_numbers and len(signals) >= 1 and "call" in text:
        score += 10
        reasons.append("Asks you to call a phone number given in the message")
        signals.append("callback_number")

    if requested_items and has_brand(text):
        score += 10
        reasons.append("Bank or payment brand used with a sensitive request")
        signals.append("brand_impersonation")

    if urls:
        score += 5
        reasons.append("Message contains a link")
        signals.append("contains_link")

    if any(is_shortened(url) for url in urls):
        score += 15
        reasons.append("Shortened link detected")
        signals.append("shortened_link")

    url_results = []
    highest_url_risk = 0

    if url_predictor:
        for url in urls[:5]:
            try:
                result, risk, url_reasons = url_predictor(url)
                highest_url_risk = max(highest_url_risk, risk)
                url_results.append({
                    "url": url,
                    "result": result,
                    "risk_score": risk,
                    "reasons": url_reasons,
                })
            except Exception:
                url_results.append({"url": url, "error": "Link could not be scanned"})

    score = max(score, highest_url_risk)

    if requested_items and highest_url_risk >= SUSPICIOUS_CUTOFF:
        score += 15
        reasons.append("Sensitive information is requested through a suspicious link")
        signals.append("credential_with_bad_link")

    # a "never share your OTP" line can lower the score only when
    # nothing else suspicious is in the message
    other_signals = [s for s in signals if s not in {"contains_link", "urgency"}]

    if safe_otp_warning and not other_signals and highest_url_risk < SUSPICIOUS_CUTOFF:
        score = min(score, 20)

    score = max(0, min(round(score), 100))

    if not reasons:
        reasons.append("No strong scam pattern detected")

    return {
        "status": message_status(score),
        "risk_score": score,
        "reasons": reasons,
        "signals": sorted(set(signals)),
        "sensitive_items_requested": requested_items,
        "urls": urls,
        "url_results": url_results,
    }
