import re


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


REQUEST_WORDS = [
    "share",
    "send",
    "tell",
    "provide",
    "forward",
    "reply",
    "give",
    "disclose",
    "enter",
    "submit",
    "confirm",
    "verify",
    "update",
]


DISCLOSURE_WORDS = [
    "share",
    "send",
    "tell",
    "provide",
    "forward",
    "reply",
    "give",
    "disclose",
]


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


SHORT_URLS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "rb.gy",
    "is.gd",
]


URL_PATTERN = re.compile(
    r"(https?://[^\s]+|www\.[^\s]+|"
    r"(?:[a-zA-Z0-9-]+\.)+"
    r"(?:com|in|org|net|co|xyz|top|click|link|site|online)"
    r"(?:/[^\s]*)?)",
    re.IGNORECASE,
)


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
    word_pattern = "|".join(
        re.escape(word) for word in words
    )

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


def is_safe_otp_message(text):
    patterns = [
        r"\bnever\s+share\s+(?:your\s+)?otp\b",
        r"\bdo not\s+share\s+(?:your\s+)?otp\b",
        r"\bdon't\s+share\s+(?:your\s+)?otp\b",
        r"\bdont\s+share\s+(?:your\s+)?otp\b",
        r"\bnever\s+disclose\s+(?:your\s+)?otp\b",
        r"\bdo not\s+disclose\s+(?:your\s+)?otp\b",
        r"\bbank\s+will\s+never\s+ask.*?\botp\b",
    ]

    return has_pattern(text, patterns)


def remove_safe_otp_warnings(text):
    patterns = [
        r"\bnever\s+share\s+(?:your\s+)?otp\b",
        r"\bdo not\s+share\s+(?:your\s+)?otp\b",
        r"\bdon't\s+share\s+(?:your\s+)?otp\b",
        r"\bdont\s+share\s+(?:your\s+)?otp\b",
        r"\bnever\s+disclose\s+(?:your\s+)?otp\b",
        r"\bdo not\s+disclose\s+(?:your\s+)?otp\b",
        r"\bbank\s+will\s+never\s+ask.*?\botp\b",
    ]

    for pattern in patterns:
        text = re.sub(
            pattern,
            "",
            text,
            flags=re.IGNORECASE,
        )

    return text


def get_requested_items(text):
    items = []

    for name, terms in SENSITIVE_TERMS.items():
        for term in terms:
            if request_near_term(
                text,
                term,
                REQUEST_WORDS,
            ):
                items.append(name)
                break

    return items


def asks_to_disclose(text, items):
    for item in items:
        for term in SENSITIVE_TERMS[item]:
            if request_near_term(
                text,
                term,
                DISCLOSURE_WORDS,
            ):
                return True

    return False


def analyze_scam_message(message, url_predictor=None):
    message = str(message).strip()

    if not message:
        raise ValueError("Message cannot be empty.")

    text = " ".join(
        message.lower().split()
    )

    score = 0
    reasons = []
    signals = []

    safe_otp_warning = is_safe_otp_message(text)

    request_text = remove_safe_otp_warnings(text)

    requested_items = get_requested_items(
        request_text
    )

    if requested_items:
        items = ", ".join(requested_items)

        if asks_to_disclose(
            request_text,
            requested_items,
        ):
            score += 55

            reasons.append(
                f"Message asks you to share sensitive information: {items}"
            )

            signals.append(
                "credential_disclosure"
            )

        else:
            score += 35

            reasons.append(
                f"Message asks for sensitive information: {items}"
            )

            signals.append(
                "credential_request"
            )

    urgency_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bright now\b",
        r"\bact now\b",
        r"\bverify now\b",
        r"\bupdate now\b",
    ]

    if has_pattern(text, urgency_patterns):
        score += 15

        reasons.append(
            "Message creates urgency or pressure"
        )

        signals.append("urgency")

    threat_patterns = [
        r"account.*(?:blocked|suspended|frozen|closed)",
        r"kyc.*(?:expired|pending|blocked|required|update)",
        r"card.*blocked",
        r"sim.*blocked",
    ]

    if has_pattern(text, threat_patterns):
        score += 20

        reasons.append(
            "Account, KYC, card, or SIM blocking threat detected"
        )

        signals.append("account_threat")

    reward_patterns = [
        r"(?:cashback|refund|reward|prize).*(?:claim|receive|credited)",
        r"won.*(?:prize|lottery|reward)",
    ]

    if has_pattern(text, reward_patterns):
        score += 15

        reasons.append(
            "Prize, cashback, refund, or reward bait detected"
        )

        signals.append("reward_bait")

    remote_patterns = [
        r"(?:anydesk|teamviewer|quicksupport|remote access|screen share)",
        r"install.*(?:app|apk).*(?:support|verify|kyc)",
    ]

    if has_pattern(text, remote_patterns):
        score += 30

        reasons.append(
            "Remote access or suspicious app installation requested"
        )

        signals.append("remote_access")

    payment_patterns = [
        r"(?:pay|transfer|send).*(?:rs\.?|inr|₹|rupee)",
        r"upi\s+(?:collect|request)",
        r"scan\s+(?:this\s+)?qr",
    ]

    if has_pattern(text, payment_patterns):
        score += 18

        reasons.append(
            "Payment or UPI request detected"
        )

        signals.append("payment_request")

    if (
        requested_items
        and any(brand in text for brand in BRANDS)
    ):
        score += 10

        reasons.append(
            "Bank or payment brand used with a sensitive request"
        )

        signals.append("brand_impersonation")

    urls = extract_urls(message)

    if urls:
        score += 5

        reasons.append(
            "Message contains a link"
        )

        signals.append("contains_link")

    shortened_link = False

    for url in urls:
        for shortener in SHORT_URLS:
            if shortener in url.lower():
                shortened_link = True
                break

        if shortened_link:
            break

    if shortened_link:
        score += 15

        reasons.append(
            "Shortened link detected"
        )

        signals.append("shortened_link")

    url_results = []
    highest_url_risk = 0

    if url_predictor:
        for url in urls[:5]:
            try:
                result, risk, url_reasons, confidence = url_predictor(url)

                highest_url_risk = max(
                    highest_url_risk,
                    risk,
                )

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

    score = max(
        score,
        highest_url_risk,
    )

    if (
        requested_items
        and highest_url_risk >= 50
    ):
        score += 15

        reasons.append(
            "Sensitive information is requested through a suspicious link"
        )

        signals.append(
            "credential_with_bad_link"
        )

    if (
        requested_items
        and "account_threat" in signals
    ):
        score += 8

    if (
        safe_otp_warning
        and not requested_items
        and highest_url_risk < 35
        and "account_threat" not in signals
        and "remote_access" not in signals
        and "payment_request" not in signals
    ):
        score = min(score, 20)

    score = max(
        0,
        min(round(score), 100),
    )

    if score >= 70:
        status = "Likely Fraud"

    elif score >= 35:
        status = "Suspicious"

    else:
        status = "Low Risk"

    confidence = min(
        52 + len(set(signals)) * 7,
        96,
    )

    if highest_url_risk >= 70:
        confidence = max(
            confidence,
            88,
        )

    if not reasons:
        reasons.append(
            "No strong scam pattern detected"
        )

    return {
        "status": status,
        "risk_score": score,
        "confidence": confidence,
        "reasons": reasons,
        "signals": sorted(set(signals)),
        "sensitive_items_requested": requested_items,
        "urls": urls,
        "url_results": url_results,
    }