"""
ScamShield AI
URL Feature Extraction Engine
"""

import os
import json
import math
import re
import ipaddress

from urllib.parse import urlparse


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

KNOWLEDGE_BASE = os.path.join(
    BASE_DIR,
    "knowledge_base"
)


# ============================================================
# LOAD JSON
# ============================================================

def load_json(filename):

    path = os.path.join(
        KNOWLEDGE_BASE,
        filename
    )

    if not os.path.exists(path):

        raise FileNotFoundError(
            f"Knowledge-base file not found: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


URL_KEYWORDS = load_json(
    "url_keywords.json"
)

URL_SHORTENERS = load_json(
    "url_shorteners.json"
)

SUSPICIOUS_TLDS = load_json(
    "suspicious_tlds.json"
)

TRUSTED_DOMAINS = load_json(
    "trusted_domains.json"
)


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(text):

    if not text:

        return 0.0

    entropy = 0.0

    for char in set(text):

        probability = (
            text.count(char)
            / len(text)
        )

        entropy -= (
            probability
            * math.log2(probability)
        )

    return entropy


# ============================================================
# IP ADDRESS CHECK
# ============================================================

def is_ip_address(hostname):

    if not hostname:

        return False

    try:

        ipaddress.ip_address(
            hostname
        )

        return True

    except ValueError:

        return False


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url):

    url = str(url).strip()

    if not url:

        return ""

    # Handle defanged URLs used in datasets
    # example.com[.]com -> example.com.com
    url = url.replace(
        "[.]",
        "."
    )

    url = url.replace(
        "(.)",
        "."
    )

    # Convert hxxp/hxxps to normal protocols

    url = re.sub(
        r"^hxxps://",
        "https://",
        url,
        flags=re.IGNORECASE
    )

    url = re.sub(
        r"^hxxp://",
        "http://",
        url,
        flags=re.IGNORECASE
    )

    # Add protocol if missing

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+\-.]*://",
        url
    ):

        url = "http://" + url

    return url


# ============================================================
# KEYWORD DETECTION
# ============================================================

def find_keywords(url):

    url = url.lower()

    matched = []

    for keyword in URL_KEYWORDS:

        if keyword.lower() in url:

            matched.append(
                keyword
            )

    return matched


# ============================================================
# SUSPICIOUS TLD
# ============================================================

def find_suspicious_tld(hostname):

    hostname = hostname.lower()

    for tld in SUSPICIOUS_TLDS:

        if hostname.endswith(
            tld.lower()
        ):

            return tld

    return ""


# ============================================================
# TRUSTED DOMAIN
# ============================================================

def is_trusted_domain(hostname):

    if not hostname:

        return False

    hostname = (
        hostname
        .lower()
        .strip(".")
    )

    for domain in TRUSTED_DOMAINS:

        domain = (
            domain
            .lower()
            .strip(".")
        )

        # Exact domain
        if hostname == domain:

            return True

        # Legitimate subdomain
        #
        # example:
        # login.google.com
        #
        # should match:
        # google.com

        if hostname.endswith(
            "." + domain
        ):

            return True

    return False


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def extract_url_features(url):

    original_url = str(
        url
    ).strip()

    normalized_url = normalize_url(
        original_url
    )

    parsed = urlparse(
        normalized_url
    )

    hostname = (
        parsed.hostname
        or ""
    )

    path = (
        parsed.path
        or ""
    )

    query = (
        parsed.query
        or ""
    )


    # ========================================================
    # BASIC MEASUREMENTS
    # ========================================================

    url_length = len(
        original_url
    )

    domain_length = len(
        hostname
    )

    path_length = len(
        path
    )

    query_length = len(
        query
    )


    # ========================================================
    # CHARACTER COUNTS
    # ========================================================

    digit_count = sum(
        char.isdigit()
        for char in original_url
    )

    letter_count = sum(
        char.isalpha()
        for char in original_url
    )

    special_character_count = sum(
        not char.isalnum()
        for char in original_url
    )


    # ========================================================
    # SYMBOL COUNTS
    # ========================================================

    dot_count = original_url.count(
        "."
    )

    hyphen_count = original_url.count(
        "-"
    )

    underscore_count = original_url.count(
        "_"
    )

    slash_count = original_url.count(
        "/"
    )

    question_mark_count = original_url.count(
        "?"
    )

    equal_count = original_url.count(
        "="
    )

    ampersand_count = original_url.count(
        "&"
    )

    percent_count = original_url.count(
        "%"
    )

    at_symbol_count = original_url.count(
        "@"
    )

    colon_count = original_url.count(
        ":"
    )


    # ========================================================
    # DOMAIN INFORMATION
    # ========================================================

    domain_parts = [

        part

        for part in hostname.split(
            "."
        )

        if part
    ]

    subdomain_count = max(
        len(domain_parts) - 2,
        0
    )


    # ========================================================
    # PROTOCOL
    # ========================================================

    https = int(
        parsed.scheme.lower()
        == "https"
    )

    http = int(
        parsed.scheme.lower()
        == "http"
    )


    # ========================================================
    # IP ADDRESS
    # ========================================================

    ip_address = int(
        is_ip_address(
            hostname
        )
    )


    # ========================================================
    # SUSPICIOUS KEYWORDS
    # ========================================================

    matched_keywords = find_keywords(
        original_url
    )

    suspicious_keyword_count = len(
        matched_keywords
    )


    # ========================================================
    # URL SHORTENER
    # ========================================================

    is_shortened = int(
        hostname.lower()
        in [
            domain.lower()
            for domain
            in URL_SHORTENERS
        ]
    )


    # ========================================================
    # SUSPICIOUS TLD
    # ========================================================

    matched_tld = (
        find_suspicious_tld(
            hostname
        )
    )

    suspicious_tld = int(
        bool(matched_tld)
    )


    # ========================================================
    # TRUSTED DOMAIN
    # ========================================================

    trusted_domain = int(
        is_trusted_domain(
            hostname
        )
    )


    # ========================================================
    # URL LENGTH
    # ========================================================

    long_url = int(
        url_length > 100
    )

    very_long_url = int(
        url_length > 200
    )


    # ========================================================
    # SUBDOMAIN COUNT
    # ========================================================

    many_subdomains = int(
        subdomain_count >= 3
    )


    # ========================================================
    # RATIOS
    # ========================================================

    digit_ratio = (

        digit_count
        / url_length

        if url_length

        else 0
    )

    letter_ratio = (

        letter_count
        / url_length

        if url_length

        else 0
    )


    # ========================================================
    # ENTROPY
    # ========================================================

    entropy = calculate_entropy(
        original_url
    )


    # ========================================================
    # QUERY PARAMETERS
    # ========================================================

    has_query = int(
        bool(query)
    )

    query_parameter_count = (

        query.count("&") + 1

        if query

        else 0
    )


    # ========================================================
    # PORT
    # ========================================================

    try:

        has_port = int(
            parsed.port is not None
        )

    except ValueError:

        has_port = 0


    # ========================================================
    # ADDITIONAL PATTERNS
    # ========================================================

    has_at_symbol = int(
        "@" in original_url
    )

    has_double_slash_path = int(
        "//" in path
    )


    # ========================================================
    # RETURN FEATURES
    # ========================================================

    return {

        "url_length":
            url_length,

        "domain_length":
            domain_length,

        "path_length":
            path_length,

        "query_length":
            query_length,

        "digit_count":
            digit_count,

        "letter_count":
            letter_count,

        "special_character_count":
            special_character_count,

        "dot_count":
            dot_count,

        "hyphen_count":
            hyphen_count,

        "underscore_count":
            underscore_count,

        "slash_count":
            slash_count,

        "question_mark_count":
            question_mark_count,

        "equal_count":
            equal_count,

        "ampersand_count":
            ampersand_count,

        "percent_count":
            percent_count,

        "at_symbol_count":
            at_symbol_count,

        "colon_count":
            colon_count,

        "subdomain_count":
            subdomain_count,

        "https":
            https,

        "http":
            http,

        "ip_address":
            ip_address,

        "suspicious_keyword_count":
            suspicious_keyword_count,

        "is_shortened":
            is_shortened,

        "suspicious_tld":
            suspicious_tld,

        "trusted_domain":
            trusted_domain,

        "long_url":
            long_url,

        "very_long_url":
            very_long_url,

        "many_subdomains":
            many_subdomains,

        "digit_ratio":
            digit_ratio,

        "letter_ratio":
            letter_ratio,

        "entropy":
            entropy,

        "has_query":
            has_query,

        "query_parameter_count":
            query_parameter_count,

        "has_port":
            has_port,

        "has_at_symbol":
            has_at_symbol,

        "has_double_slash_path":
            has_double_slash_path,

        # Information for explanation
        "matched_keywords":
            matched_keywords,

        "matched_tld":
            matched_tld,

        "clean_url":
            original_url
    }


# ============================================================
# MODEL FEATURE NAMES
# ============================================================

FEATURE_NAMES = [

    "url_length",

    "domain_length",

    "path_length",

    "query_length",

    "digit_count",

    "letter_count",

    "special_character_count",

    "dot_count",

    "hyphen_count",

    "underscore_count",

    "slash_count",

    "question_mark_count",

    "equal_count",

    "ampersand_count",

    "percent_count",

    "at_symbol_count",

    "colon_count",

    "subdomain_count",

    "https",

    "http",

    "ip_address",

    "suspicious_keyword_count",

    "is_shortened",

    "suspicious_tld",

    "trusted_domain",

    "long_url",

    "very_long_url",

    "many_subdomains",

    "digit_ratio",

    "letter_ratio",

    "entropy",

    "has_query",

    "query_parameter_count",

    "has_port",

    "has_at_symbol",

    "has_double_slash_path"
]


# ============================================================
# BUILD MODEL FEATURES
# ============================================================

def build_features(url):

    features = extract_url_features(
        url
    )

    numeric_features = [

        features[name]

        for name
        in FEATURE_NAMES
    ]

    return {

        "numeric_features":
            numeric_features,

        "feature_names":
            FEATURE_NAMES,

        "matched_keywords":
            features[
                "matched_keywords"
            ],

        "matched_tld":
            features[
                "matched_tld"
            ],

        "trusted_domain":
            features[
                "trusted_domain"
            ],

        "clean_url":
            features[
                "clean_url"
            ]
    }


# ============================================================
# TEST FEATURE ENGINE
# ============================================================

if __name__ == "__main__":

    print()

    print("=" * 70)
    print(
        "SCAMSHIELD AI - URL FEATURE ENGINE"
    )
    print("=" * 70)

    print()

    url = input(
        "Enter URL: "
    ).strip()

    try:

        result = build_features(
            url
        )

        print()

        print("=" * 70)
        print(
            "FEATURE RESULT"
        )
        print("=" * 70)

        print()

        print(
            "URL:",
            result["clean_url"]
        )

        print()

        print(
            "Trusted Domain:",
            "YES"
            if result["trusted_domain"]
            else "NO"
        )

        print()

        print(
            "Matched Keywords:"
        )

        if result[
            "matched_keywords"
        ]:

            print(
                result[
                    "matched_keywords"
                ]
            )

        else:

            print(
                "None"
            )

        print()

        print(
            "Suspicious TLD:"
        )

        if result[
            "matched_tld"
        ]:

            print(
                result[
                    "matched_tld"
                ]
            )

        else:

            print(
                "None"
            )

        print()

        print(
            "Numeric Features:"
        )

        print()

        for name, value in zip(

            result[
                "feature_names"
            ],

            result[
                "numeric_features"
            ]
        ):

            print(
                f"{name:32} : {value}"
            )

        print()

        print("=" * 70)
        print(
            "FEATURE EXTRACTION COMPLETED"
        )
        print("=" * 70)

    except Exception as error:

        print()

        print("=" * 70)
        print("ERROR")
        print("=" * 70)

        print()

        print(error)