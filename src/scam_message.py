import re

import tldextract

from features import SHORTENERS


MAX_MESSAGE_LENGTH = 3000


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
]


SHORT_PATTERN = "|".join(re.escape(domain) for domain in SHORTENERS)

URL_PATTERN = re.compile(
    r"(https?://[^\s]+|www\.[^\s]+|"
    rf"\b(?:{SHORT_PATTERN})(?=[/\s.,;:!?)]|$)(?:/[^\s]*)?|"
    r"(?:[a-zA-Z0-9-]+\.)+"
    r"(?:com|in|org|net|co|xyz|top|click|link|site|online)\b"
    r"(?:/[^\s]*)?)",
    re.IGNORECASE,
)


SAFE_OTP_PATTERNS = [
    r"\bnever\s+share\s+(?:your\s+)?otp\b",
    r"\bdo not\s+share\s+(?:your\s+)?otp\b",
    r"\bdon't\s+share\s+(?:your\s+)?otp\b",
    r"\bdont\s+share\s+(?:your\s+)?otp\b",
    r"\bnever\s+disclose\s+(?:your\s+)?otp\b",
    r"\bdo not\s+disclose\s+(?:your\s+)?otp\b",
    r"\bbank\s+will\s+never\s+ask.{0,40}?\botp\b",
]

# message that is just giving an OTP, like "Your OTP is 458921"
OTP_DELIVERY_PATTERNS = [
    r"\b(?:otp|verification code|one[- ]time password)\b\D{0,25}\b\d{4,8}\b",
    r"\b\d{4,8}\b\D{0,25}\b(?:otp|verification code|one[- ]time password)\b",
]


def extract_urls(message):
    urls = []

    for url in URL_PATTERN.findall(message):
        url = url.rstrip(".,);]}!?")

        if url.lower().startswith("www."):
            url = "https://" + url

        elif not url.lower().startswith(("http://", "https://")):
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
    extracted = tldextract.extract(url.lower())
    root_domain = f"{extracted.domain}.{extracted.suffix}"

    return root_domain in SHORTENERS


def get_confidence(score):
    # not a real probability, only how far the score is from the
    # status cutoffs (35 and 70). near a cutoff = less sure
    distance = min(abs(score - 35), abs(score - 70), 30)

    return round(50 + distance * 1.5)


def analyze_scam_message(message, url_predictor=None):
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
            reasons.append(
                f"Message asks you to share sensitive information: {items}"
            )
            signals.append("credential_disclosure")

        else:
            score += 35
            reasons.append(
                f"Message asks for sensitive information: {items}"
            )
            signals.append("credential_request")

    urgency_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bright now\b",
        r"\bact now\b",
        r"\bverify now\b",
        r"\bupdate now\b",
        r"\bturant\b",
        r"\bjaldi\b",
    ]

    if has_pattern(text, urgency_patterns):
        score += 15
        reasons.append("Message creates urgency or pressure")
        signals.append("urgency")

    threat_patterns = [
        r"account.{0,80}(?:blocked|suspended|frozen|closed)",
        r"kyc.{0,80}(?:expired|pending|blocked|required|update)",
        r"card.{0,80}blocked",
        r"sim.{0,80}blocked",
        r"(?:account|khata|card|sim).{0,40}(?:band|block)\s+ho",
    ]

    if has_pattern(text, threat_patterns):
        score += 20
        reasons.append("Account, KYC, card, or SIM blocking threat detected")
        signals.append("account_threat")

    reward_patterns = [
        r"(?:cashback|refund|reward|prize).{0,80}(?:claim|receive|credited)",
        r"won.{0,80}(?:prize|lottery|reward)",
    ]

    if has_pattern(text, reward_patterns):
        score += 15
        reasons.append("Prize, cashback, refund, or reward bait detected")
        signals.append("reward_bait")

    remote_patterns = [
        r"(?:anydesk|teamviewer|quicksupport|remote access|screen share)",
        r"install.{0,40}(?:app|apk).{0,40}(?:support|verify|kyc)",
    ]

    if has_pattern(text, remote_patterns):
        score += 30
        reasons.append("Remote access or suspicious app installation requested")
        signals.append("remote_access")

    payment_patterns = [
        r"(?:pay|transfer|send).{0,60}(?:rs\.?|inr|₹|rupee)",
        r"upi\s+(?:collect|request)",
        r"scan\s+(?:this\s+)?qr",
    ]

    if has_pattern(text, payment_patterns):
        score += 18
        reasons.append("Payment or UPI request detected")
        signals.append("payment_request")

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
                result, risk, url_reasons, confidence = url_predictor(url)

                highest_url_risk = max(highest_url_risk, risk)

                url_results.append({
                    "url": url,
                    "result": result,
                    "risk_score": risk,
                    "confidence": confidence,
                    "reasons": url_reasons,
                })

            except Exception as error:
                url_results.append({
                    "url": url,
                    "error": str(error),
                })

    score = max(score, highest_url_risk)

    if requested_items and highest_url_risk >= 50:
        score += 15
        reasons.append(
            "Sensitive information is requested through a suspicious link"
        )
        signals.append("credential_with_bad_link")

    if requested_items and "account_threat" in signals:
        score += 8

    # a "never share your OTP" line can lower the score only when
    # nothing else suspicious is in the message
    other_signals = [s for s in signals if s != "contains_link"]

    if safe_otp_warning and not other_signals and highest_url_risk < 35:
        score = min(score, 20)

    score = max(0, min(round(score), 100))

    if score >= 70:
        status = "Likely Fraud"
    elif score >= 35:
        status = "Suspicious"
    else:
        status = "Low Risk"

    if not reasons:
        reasons.append("No strong scam pattern detected")

    return {
        "status": status,
        "risk_score": score,
        "confidence": get_confidence(score),
        "reasons": reasons,
        "signals": sorted(set(signals)),
        "sensitive_items_requested": requested_items,
        "urls": urls,
        "url_results": url_results,
    }
