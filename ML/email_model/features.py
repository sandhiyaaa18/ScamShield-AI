"""
ScamShield AI
Email Feature Engine

Purpose:
    Extract features from emails for ScamShield AI.

Compatible with:
    - .eml files
    - raw email text
    - shared knowledge_base JSON files
    - weighted scam_keywords.json
    - scam_rules.json
    - entities.json

IMPORTANT:
    This file does NOT modify the SMS model.
"""

import os
import re
import json
import math
from collections import Counter
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(__file__)
)

KNOWLEDGE_BASE_DIR = os.path.join(
    BASE_DIR,
    "knowledge_base"
)

SCAM_KEYWORDS_PATH = os.path.join(
    KNOWLEDGE_BASE_DIR,
    "scam_keywords.json"
)

SCAM_RULES_PATH = os.path.join(
    KNOWLEDGE_BASE_DIR,
    "scam_rules.json"
)

ENTITIES_PATH = os.path.join(
    KNOWLEDGE_BASE_DIR,
    "entities.json"
)

PHISHING_DOMAINS_PATH = os.path.join(
    KNOWLEDGE_BASE_DIR,
    "phishing_domains.json"
)

SUSPICIOUS_TLDS_PATH = os.path.join(
    KNOWLEDGE_BASE_DIR,
    "suspicious_tlds.json"
)


# ============================================================
# JSON LOADER
# ============================================================

def load_json(path, default=None):
    """
    Safely load a JSON file.

    Returns default if:
        - file does not exist
        - file is empty
        - JSON is invalid
    """

    if default is None:
        default = {}

    if not os.path.exists(path):
        print(f"Warning: JSON file not found: {path}")
        return default

    try:
        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            content = file.read().strip()

            if not content:
                print(f"Warning: JSON file is empty: {path}")
                return default

            return json.loads(content)

    except json.JSONDecodeError as error:

        print(
            f"Warning: Invalid JSON in {path}: {error}"
        )

        return default

    except Exception as error:

        print(
            f"Warning: Could not load {path}: {error}"
        )

        return default


# ============================================================
# LOAD KNOWLEDGE BASE
# ============================================================

SCAM_KEYWORDS = load_json(
    SCAM_KEYWORDS_PATH,
    {}
)

SCAM_RULES = load_json(
    SCAM_RULES_PATH,
    {}
)

ENTITIES = load_json(
    ENTITIES_PATH,
    {}
)

PHISHING_DOMAINS = load_json(
    PHISHING_DOMAINS_PATH,
    []
)

SUSPICIOUS_TLDS = load_json(
    SUSPICIOUS_TLDS_PATH,
    []
)


# ============================================================
# EMAIL PARSER
# ============================================================

def parse_eml(file_path):
    """
    Parse an .eml file.

    Returns:
        dictionary containing email metadata and body.
    """

    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"Email file not found: {file_path}"
        )

    with open(
        file_path,
        "rb"
    ) as file:

        message = BytesParser(
            policy=policy.default
        ).parse(file)

    sender = message.get(
        "From",
        ""
    )

    recipient = message.get(
        "To",
        ""
    )

    reply_to = message.get(
        "Reply-To",
        ""
    )

    subject = message.get(
        "Subject",
        ""
    )

    date = message.get(
        "Date",
        ""
    )

    plain_parts = []
    html_parts = []

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            try:

                content = part.get_content()

            except Exception:

                try:
                    content = part.get_payload(
                        decode=True
                    )

                    if isinstance(
                        content,
                        bytes
                    ):
                        content = content.decode(
                            errors="ignore"
                        )

                except Exception:
                    content = ""

            if not content:
                continue

            if content_type == "text/plain":

                plain_parts.append(
                    str(content)
                )

            elif content_type == "text/html":

                html_parts.append(
                    str(content)
                )

    else:

        try:

            content = message.get_content()

        except Exception:

            content = ""

        if message.get_content_type() == "text/html":

            html_parts.append(
                str(content)
            )

        else:

            plain_parts.append(
                str(content)
            )

    plain_text = "\n".join(
        plain_parts
    )

    html_text = "\n".join(
        html_parts
    )

    return {
        "sender": sender,
        "recipient": recipient,
        "reply_to": reply_to,
        "subject": subject,
        "date": date,
        "plain_text": plain_text,
        "html_text": html_text
    }


# ============================================================
# HTML CLEANING
# ============================================================

def remove_html(text):
    """
    Convert HTML into readable text.
    """

    if not text:
        return ""

    text = re.sub(
        r"<script.*?>.*?</script>",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL
    )

    text = re.sub(
        r"<style.*?>.*?</style>",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL
    )

    text = re.sub(
        r"<[^>]+>",
        " ",
        text
    )

    text = text.replace(
        "&nbsp;",
        " "
    )

    text = text.replace(
        "&amp;",
        "&"
    )

    text = text.replace(
        "&lt;",
        "<"
    )

    text = text.replace(
        "&gt;",
        ">"
    )

    return text


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def clean_text(text):
    """
    Normalize email text.
    """

    if not text:
        return ""

    text = remove_html(
        str(text)
    )

    text = text.lower()

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):

    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+|www\.[^\s<>\"]+"

    urls = re.findall(
        pattern,
        text,
        flags=re.IGNORECASE
    )

    cleaned = []

    for url in urls:

        url = url.rstrip(
            ".,!?;:)]}"
        )

        cleaned.append(
            url
        )

    return list(
        dict.fromkeys(cleaned)
    )


# ============================================================
# EMAIL EXTRACTION
# ============================================================

def extract_email_addresses(text):

    if not text:
        return []

    pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

    return list(
        dict.fromkeys(
            re.findall(
                pattern,
                text
            )
        )
    )


# ============================================================
# PHONE EXTRACTION
# ============================================================

def extract_phone_numbers(text):

    if not text:
        return []

    pattern = r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"

    return list(
        dict.fromkeys(
            re.findall(
                pattern,
                text
            )
        )
    )


# ============================================================
# MONEY EXTRACTION
# ============================================================

def extract_money(text):

    if not text:
        return []

    pattern = (
        r"(?:₹|rs\.?|inr|\$|usd|eur|€|£)"
        r"\s*[\d,]+(?:\.\d+)?"
    )

    return re.findall(
        pattern,
        text,
        flags=re.IGNORECASE
    )


# ============================================================
# NUMBER EXTRACTION
# ============================================================

def extract_numbers(text):

    if not text:
        return []

    return re.findall(
        r"\b\d+\b",
        text
    )


# ============================================================
# TOKENIZATION
# ============================================================

def tokenize(text):

    if not text:
        return []

    return re.findall(
        r"\b[a-zA-Z0-9']+\b",
        text.lower()
    )


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(text):

    if not text:
        return 0.0

    counts = Counter(
        text
    )

    total = len(text)

    entropy = 0.0

    for count in counts.values():

        probability = count / total

        entropy -= (
            probability *
            math.log2(
                probability
            )
        )

    return entropy


# ============================================================
# REPEATED CHARACTER COUNT
# ============================================================

def repeated_character_count(text):

    if not text:
        return 0

    matches = re.findall(
        r"(.)\1{2,}",
        text
    )

    return len(matches)


# ============================================================
# UPPERCASE RATIO
# ============================================================

def uppercase_ratio(text):

    letters = [
        char
        for char in text
        if char.isalpha()
    ]

    if not letters:
        return 0.0

    uppercase = sum(
        char.isupper()
        for char in letters
    )

    return uppercase / len(
        letters
    )


# ============================================================
# DIGIT RATIO
# ============================================================

def digit_ratio(text):

    if not text:
        return 0.0

    digits = sum(
        char.isdigit()
        for char in text
    )

    return digits / len(
        text
    )


# ============================================================
# SPECIAL CHARACTER COUNT
# ============================================================

def special_character_count(text):

    if not text:
        return 0

    return len(
        re.findall(
            r"[^a-zA-Z0-9\s]",
            text
        )
    )


# ============================================================
# KEYWORD ITERATOR
# ============================================================

def iter_keywords(data):
    """
    Supports both:

        {
            "otp": 7,
            "urgent": 5
        }

    and:

        {
            "financial": [
                "otp",
                "cvv"
            ]
        }

    and:

        {
            "financial": {
                "weight": 10,
                "keywords": [
                    "otp",
                    "cvv"
                ]
            }
        }
    """

    if not isinstance(
        data,
        dict
    ):
        return

    for key, value in data.items():

        # ------------------------------------------------
        # Flat weighted dictionary
        # ------------------------------------------------

        if isinstance(
            value,
            (int, float)
        ):

            yield (
                str(key),
                float(value)
            )

        # ------------------------------------------------
        # Category list
        # ------------------------------------------------

        elif isinstance(
            value,
            list
        ):

            for item in value:

                if isinstance(
                    item,
                    str
                ):

                    yield (
                        item,
                        1.0
                    )

        # ------------------------------------------------
        # Category object
        # ------------------------------------------------

        elif isinstance(
            value,
            dict
        ):

            weight = value.get(
                "weight",
                1
            )

            keywords = value.get(
                "keywords",
                []
            )

            if isinstance(
                keywords,
                list
            ):

                for item in keywords:

                    if isinstance(
                        item,
                        str
                    ):

                        try:
                            item_weight = float(
                                weight
                            )
                        except (
                            TypeError,
                            ValueError
                        ):
                            item_weight = 1.0

                        yield (
                            item,
                            item_weight
                        )


# ============================================================
# MATCH SCAM KEYWORDS
# ============================================================

def match_scam_keywords(text):

    text_lower = text.lower()

    matched_keywords = []

    total_score = 0.0

    for keyword, weight in iter_keywords(
        SCAM_KEYWORDS
    ):

        keyword = keyword.lower().strip()

        if not keyword:
            continue

        if keyword in text_lower:

            matched_keywords.append(
                keyword
            )

            total_score += weight

    # Remove duplicates
    matched_keywords = list(
        dict.fromkeys(
            matched_keywords
        )
    )

    return (
        matched_keywords,
        total_score
    )


# ============================================================
# MATCH SCAM RULES
# ============================================================

def match_scam_rules(text):

    text_lower = text.lower()

    matched_rules = []

    rule_score = 0.0

    if not isinstance(
        SCAM_RULES,
        dict
    ):
        return (
            matched_rules,
            rule_score
        )

    for rule_name, rule_data in SCAM_RULES.items():

        weight = 1.0
        keywords = []

        # --------------------------------------------
        # Normal rule structure
        # --------------------------------------------

        if isinstance(
            rule_data,
            dict
        ):

            weight = rule_data.get(
                "weight",
                1
            )

            keywords = rule_data.get(
                "keywords",
                []
            )

        elif isinstance(
            rule_data,
            list
        ):

            keywords = rule_data

        if not isinstance(
            keywords,
            list
        ):
            continue

        matched = False

        for keyword in keywords:

            if not isinstance(
                keyword,
                str
            ):
                continue

            if keyword.lower() in text_lower:

                matched = True
                break

        if matched:

            matched_rules.append(
                rule_name
            )

            try:

                rule_score += float(
                    weight
                )

            except (
                TypeError,
                ValueError
            ):

                rule_score += 1.0

    return (
        matched_rules,
        rule_score
    )


# ============================================================
# ENTITY DETECTION
# ============================================================

def detect_entities(text):

    text_lower = text.lower()

    detected = {}

    if not isinstance(
        ENTITIES,
        dict
    ):
        return detected

    for entity_type, values in ENTITIES.items():

        matches = []

        if isinstance(
            values,
            list
        ):

            for value in values:

                if not isinstance(
                    value,
                    str
                ):
                    continue

                if value.lower() in text_lower:

                    matches.append(
                        value
                    )

        elif isinstance(
            values,
            dict
        ):

            for name, patterns in values.items():

                if isinstance(
                    patterns,
                    list
                ):

                    for pattern in patterns:

                        if (
                            isinstance(
                                pattern,
                                str
                            )
                            and
                            pattern.lower()
                            in text_lower
                        ):

                            matches.append(
                                pattern
                            )

                elif isinstance(
                    patterns,
                    str
                ):

                    if (
                        patterns.lower()
                        in text_lower
                    ):

                        matches.append(
                            patterns
                        )

        if matches:

            detected[
                entity_type
            ] = list(
                dict.fromkeys(
                    matches
                )
            )

    return detected


# ============================================================
# PHISHING DOMAIN DETECTION
# ============================================================

def detect_phishing_domains(urls):

    matched_domains = []

    domains = PHISHING_DOMAINS

    if isinstance(
        domains,
        dict
    ):
        domains = list(
            domains.keys()
        )

    if not isinstance(
        domains,
        list
    ):
        domains = []

    for url in urls:

        url_lower = url.lower()

        for domain in domains:

            if not isinstance(
                domain,
                str
            ):
                continue

            if domain.lower() in url_lower:

                matched_domains.append(
                    domain
                )

    return list(
        dict.fromkeys(
            matched_domains
        )
    )


# ============================================================
# SUSPICIOUS TLD DETECTION
# ============================================================

def detect_suspicious_tlds(urls):

    matched_tlds = []

    tlds = SUSPICIOUS_TLDS

    if isinstance(
        tlds,
        dict
    ):
        tlds = list(
            tlds.keys()
        )

    if not isinstance(
        tlds,
        list
    ):
        tlds = []

    for url in urls:

        url_lower = url.lower()

        for tld in tlds:

            if not isinstance(
                tld,
                str
            ):
                continue

            tld = tld.lower()

            if tld.startswith("."):

                if tld in url_lower:

                    matched_tlds.append(
                        tld
                    )

            else:

                if (
                    "." + tld
                    in url_lower
                ):

                    matched_tlds.append(
                        tld
                    )

    return list(
        dict.fromkeys(
            matched_tlds
        )
    )


# ============================================================
# SCAM-SPECIFIC SCORES
# ============================================================

def calculate_category_scores(
    text,
    matched_keywords
):

    text_lower = text.lower()

    def count_terms(terms):

        count = 0

        for term in terms:

            if term in text_lower:
                count += 1

        return count

    urgency_terms = [
        "urgent",
        "immediately",
        "now",
        "today",
        "expire",
        "expired",
        "suspended",
        "blocked",
        "deactivated"
    ]

    verification_terms = [
        "verify",
        "verification",
        "confirm",
        "validate",
        "kyc",
        "identity",
        "authenticate"
    ]

    financial_terms = [
        "bank",
        "payment",
        "upi",
        "credit card",
        "debit card",
        "loan",
        "refund",
        "cashback",
        "investment"
    ]

    threat_terms = [
        "police",
        "court",
        "legal action",
        "penalty",
        "fine",
        "arrest",
        "blacklisted",
        "terminate"
    ]

    reward_terms = [
        "winner",
        "won",
        "reward",
        "gift",
        "prize",
        "lottery",
        "jackpot",
        "cashback"
    ]

    action_terms = [
        "click",
        "tap",
        "download",
        "install",
        "visit",
        "scan qr",
        "open link"
    ]

    sensitive_terms = [
        "otp",
        "password",
        "cvv",
        "pin",
        "account number",
        "ifsc",
        "security code"
    ]

    return {

        "urgency_score":
            count_terms(
                urgency_terms
            ),

        "verification_score":
            count_terms(
                verification_terms
            ),

        "financial_score":
            count_terms(
                financial_terms
            ),

        "threat_score":
            count_terms(
                threat_terms
            ),

        "reward_score":
            count_terms(
                reward_terms
            ),

        "action_score":
            count_terms(
                action_terms
            ),

        "sensitive_information_score":
            count_terms(
                sensitive_terms
            ),

        "keyword_score":
            len(
                matched_keywords
            )
    }


# ============================================================
# BUILD FEATURES
# ============================================================

def build_features(
    email_input,
    sender="",
    subject="",
    recipient="",
    reply_to=""
):
    """
    Main feature extraction function.

    email_input can be:

        1. Path to .eml file
        2. Raw email text
        3. Plain message text
    """

    # ========================================================
    # If input is an .eml file
    # ========================================================

    if (
        isinstance(
            email_input,
            str
        )
        and
        email_input.lower().endswith(
            ".eml"
        )
        and
        os.path.exists(
            email_input
        )
    ):

        email_data = parse_eml(
            email_input
        )

        sender = email_data[
            "sender"
        ]

        recipient = email_data[
            "recipient"
        ]

        reply_to = email_data[
            "reply_to"
        ]

        subject = email_data[
            "subject"
        ]

        plain_text = email_data[
            "plain_text"
        ]

        html_text = email_data[
            "html_text"
        ]

        body = (
            plain_text
            + " "
            + html_text
        )

    else:

        body = str(
            email_input
            or ""
        )

    # ========================================================
    # Combined text
    # ========================================================

    combined_text = " ".join(
        [
            sender,
            recipient,
            reply_to,
            subject,
            body
        ]
    )

    cleaned = clean_text(
        combined_text
    )

    # ========================================================
    # Basic statistics
    # ========================================================

    tokens = tokenize(
        cleaned
    )

    unique_tokens = set(
        tokens
    )

    words = len(
        tokens
    )

    chars = len(
        cleaned
    )

    average_word_length = (
        sum(
            len(word)
            for word in tokens
        )
        / words
        if words > 0
        else 0
    )

    lexical_diversity = (
        len(unique_tokens)
        / words
        if words > 0
        else 0
    )

    # ========================================================
    # URLs
    # ========================================================

    urls = extract_urls(
        combined_text
    )

    phishing_domains = (
        detect_phishing_domains(
            urls
        )
    )

    suspicious_tlds = (
        detect_suspicious_tlds(
            urls
        )
    )

    # ========================================================
    # Other entities
    # ========================================================

    email_addresses = (
        extract_email_addresses(
            combined_text
        )
    )

    phone_numbers = (
        extract_phone_numbers(
            combined_text
        )
    )

    money_values = (
        extract_money(
            combined_text
        )
    )

    numbers = (
        extract_numbers(
            combined_text
        )
    )

    # ========================================================
    # Scam keywords
    # ========================================================

    matched_keywords, keyword_score = (
        match_scam_keywords(
            cleaned
        )
    )

    # ========================================================
    # Scam rules
    # ========================================================

    matched_rules, rule_score = (
        match_scam_rules(
            cleaned
        )
    )

    # ========================================================
    # Entities
    # ========================================================

    entities = detect_entities(
        cleaned
    )

    # ========================================================
    # Category scores
    # ========================================================

    category_scores = (
        calculate_category_scores(
            cleaned,
            matched_keywords
        )
    )

    # ========================================================
    # Numeric features
    # ========================================================

    numeric_features = [

        # Basic
        chars,
        words,
        len(urls),
        len(email_addresses),
        len(phone_numbers),
        len(money_values),
        len(numbers),

        # Text statistics
        uppercase_ratio(
            combined_text
        ),

        digit_ratio(
            combined_text
        ),

        special_character_count(
            combined_text
        ),

        repeated_character_count(
            combined_text
        ),

        average_word_length,

        calculate_entropy(
            cleaned
        ),

        len(tokens),

        len(unique_tokens),

        lexical_diversity,

        # Scam indicators
        len(matched_keywords),

        category_scores[
            "financial_score"
        ],

        category_scores[
            "action_score"
        ],

        category_scores[
            "urgency_score"
        ],

        # Scam specific
        category_scores[
            "verification_score"
        ],

        category_scores[
            "threat_score"
        ],

        category_scores[
            "reward_score"
        ],

        category_scores[
            "sensitive_information_score"
        ],

        category_scores[
            "financial_score"
        ],

        # Rule / entity
        rule_score,

        len(entities),

        # URL intelligence
        len(phishing_domains),

        len(suspicious_tlds),

        # Weighted keyword score
        keyword_score
    ]

    # ========================================================
    # Feature names
    # ========================================================

    feature_names = [

        "char_count",
        "word_count",
        "url_count",
        "email_count",
        "phone_count",
        "money_count",
        "number_count",

        "uppercase_ratio",
        "digit_ratio",

        "special_character_count",
        "repeated_character_count",
        "average_word_length",

        "entropy",
        "token_count",
        "unique_tokens",
        "lexical_diversity",

        "suspicious_keyword_count",
        "financial_keyword_count",
        "action_keyword_count",
        "urgency_keyword_count",

        "verification_score",
        "threat_score",
        "reward_score",
        "sensitive_information_score",
        "financial_score",

        "rule_score",
        "entity_count",

        "phishing_domain_count",
        "suspicious_tld_count",

        "keyword_score"
    ]

    # ========================================================
    # Return
    # ========================================================

    return {

        "clean_text": cleaned,

        "numeric_features":
            numeric_features,

        "feature_names":
            feature_names,

        # Email metadata
        "sender":
            sender,

        "recipient":
            recipient,

        "reply_to":
            reply_to,

        "subject":
            subject,

        # Extracted data
        "urls":
            urls,

        "email_addresses":
            email_addresses,

        "phone_numbers":
            phone_numbers,

        "money_values":
            money_values,

        "numbers":
            numbers,

        # Intelligence
        "phishing_domains":
            phishing_domains,

        "suspicious_tlds":
            suspicious_tlds,

        # Scam information
        "matched_keywords":
            matched_keywords,

        "matched_rules":
            matched_rules,

        "entities":
            entities,

        # Scores
        "keyword_score":
            keyword_score,

        "rule_score":
            rule_score,

        "urgency_score":
            category_scores[
                "urgency_score"
            ],

        "verification_score":
            category_scores[
                "verification_score"
            ],

        "financial_score":
            category_scores[
                "financial_score"
            ],

        "threat_score":
            category_scores[
                "threat_score"
            ],

        "reward_score":
            category_scores[
                "reward_score"
            ],

        "action_score":
            category_scores[
                "action_score"
            ],

        "sensitive_information_score":
            category_scores[
                "sensitive_information_score"
            ],

        # Total indicators
        "scam_indicator_count":
            (
                len(matched_keywords)
                +
                len(matched_rules)
                +
                len(phishing_domains)
                +
                len(suspicious_tlds)
            )
    }


# ============================================================
# COMMAND LINE TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("SCAMSHIELD AI - EMAIL FEATURE ENGINE")
    print("=" * 70)
    print()

    file_path = input(
        "Enter .eml file path:\n\n"
    ).strip()

    try:

        result = build_features(
            file_path
        )

        print()
        print("=" * 70)
        print("EMAIL INFORMATION")
        print("=" * 70)

        print()
        print(
            "Sender    :",
            result["sender"]
        )

        print(
            "Recipient :",
            result["recipient"]
        )

        print(
            "Reply-To  :",
            result["reply_to"]
        )

        print(
            "Subject   :",
            result["subject"]
        )

        print()
        print("=" * 70)
        print("EXTRACTED FEATURES")
        print("=" * 70)

        print()

        for name, value in zip(
            result["feature_names"],
            result["numeric_features"]
        ):

            print(
                f"{name:35}: {value}"
            )

        print()
        print("=" * 70)
        print("SCAM INTELLIGENCE")
        print("=" * 70)

        print()

        print(
            "Matched Keywords:"
        )

        print(
            result["matched_keywords"]
        )

        print()

        print(
            "Matched Rules:"
        )

        print(
            result["matched_rules"]
        )

        print()

        print(
            "Entities:"
        )

        print(
            result["entities"]
        )

        print()

        print(
            "Phishing Domains:"
        )

        print(
            result["phishing_domains"]
        )

        print()

        print(
            "Suspicious TLDs:"
        )

        print(
            result["suspicious_tlds"]
        )

        print()

        print(
            "Keyword Score :",
            result["keyword_score"]
        )

        print(
            "Rule Score    :",
            result["rule_score"]
        )

        print(
            "Total Indicators :",
            result[
                "scam_indicator_count"
            ]
        )

        print()
        print("=" * 70)
        print("FEATURE EXTRACTION COMPLETED")
        print("=" * 70)
        print()

    except Exception as error:

        print()
        print("=" * 70)
        print("ERROR")
        print("=" * 70)
        print()
        print(error)
        print()