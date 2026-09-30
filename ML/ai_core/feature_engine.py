"""
=========================================================
ScamShield AI
Advanced Feature Engine
=========================================================
"""

import math
from collections import Counter
import json
import os

from ML.ai_core.preprocessing import preprocess
from ML.ai_core.entity_engine import detect_entities
from ML.ai_core.rule_engine import evaluate_rules


# =====================================================
# Load Feature Knowledge Base
# =====================================================

KB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "knowledge_base",
    "feature_keywords.json"
)

with open(KB_PATH, "r", encoding="utf-8") as f:
    FEATURE_KEYWORDS = json.load(f)


BANK_KEYWORDS = FEATURE_KEYWORDS["bank_keywords"]
UPI_KEYWORDS = FEATURE_KEYWORDS["upi_keywords"]
URGENCY_WORDS = FEATURE_KEYWORDS["urgency_words"]
THREAT_WORDS = FEATURE_KEYWORDS["threat_words"]
VERIFY_WORDS = FEATURE_KEYWORDS["verify_words"]
REWARD_WORDS = FEATURE_KEYWORDS["reward_words"]
FINANCIAL_WORDS = FEATURE_KEYWORDS["financial_words"]
GOVERNMENT_WORDS = FEATURE_KEYWORDS["government_words"]
BRAND_WORDS = FEATURE_KEYWORDS["brand_words"]


# =====================================================
# Existing Scam Keywords
# =====================================================

SUSPICIOUS_WORDS = [

    "verify",
    "click",
    "otp",
    "bank",
    "account",
    "password",
    "login",
    "urgent",
    "winner",
    "claim",
    "loan",
    "kyc",
    "payment",
    "upi",
    "credit",
    "debit",
    "refund",
    "reward",
    "gift",
    "lottery"

]


ACTION_WORDS = {

    "click",
    "verify",
    "claim",
    "download",
    "install",
    "login",
    "pay",
    "scan",
    "update"

}


# =====================================================
# Keyword Scoring
# =====================================================

def keyword_score(text, keywords):

    text = text.lower()

    score = 0

    for keyword in keywords:

        if keyword.lower() in text:
            score += 1

    return score


# =====================================================
# Token Keyword Count
# =====================================================

def keyword_count(tokens, dictionary):

    dictionary = {
        word.lower()
        for word in dictionary
    }

    return sum(
        token.lower() in dictionary
        for token in tokens
    )


# =====================================================
# Entropy
# =====================================================

def entropy(text):

    if not text:
        return 0

    counts = Counter(text)

    total = len(text)

    ent = 0

    for value in counts.values():

        probability = value / total

        ent -= probability * math.log2(
            probability
        )

    return round(ent, 3)


# =====================================================
# Main Feature Extraction
# =====================================================

def extract_features(text):

    # =================================================
    # Preprocessing
    # =================================================

    preprocess_result = preprocess(text)

    clean_text = preprocess_result["clean_text"]

    tokens = preprocess_result["tokens"]

    stats = preprocess_result["statistics"]


    # =================================================
    # Entity Detection
    # =================================================

    entity_result = detect_entities(
        clean_text
    )


    # =================================================
    # Rule Engine
    # =================================================

    rule_result = evaluate_rules(
        clean_text
    )


    features = {}


    # =================================================
    # Basic Features
    # =================================================

    features["clean_text"] = clean_text

    features["tokens"] = tokens

    features["char_count"] = stats["char_count"]

    features["word_count"] = stats["word_count"]

    features["url_count"] = stats["url_count"]

    features["email_count"] = stats["email_count"]

    features["phone_count"] = stats["phone_count"]

    features["money_count"] = stats["money_count"]

    features["number_count"] = stats["number_count"]

    features["uppercase_ratio"] = stats[
        "uppercase_ratio"
    ]

    features["digit_ratio"] = stats[
        "digit_ratio"
    ]

    features["special_character_count"] = stats[
        "special_character_count"
    ]

    features["repeated_character_count"] = stats[
        "repeated_character_count"
    ]

    features["average_word_length"] = stats[
        "average_word_length"
    ]


    # =================================================
    # Advanced Text Features
    # =================================================

    features["entropy"] = entropy(
        clean_text
    )

    features["token_count"] = len(
        tokens
    )

    features["unique_tokens"] = len(
        set(tokens)
    )

    features["lexical_diversity"] = round(

        len(set(tokens))
        / max(len(tokens), 1),

        3

    )


    # =================================================
    # Existing Scam Features
    # =================================================

    features["suspicious_keyword_count"] = keyword_count(

        tokens,

        SUSPICIOUS_WORDS

    )

    features["financial_keyword_count"] = keyword_count(

        tokens,

        FINANCIAL_WORDS

    )

    features["action_keyword_count"] = keyword_count(

        tokens,

        ACTION_WORDS

    )

    features["urgency_keyword_count"] = keyword_count(

        tokens,

        URGENCY_WORDS

    )


    # =================================================
    # NEW SCAM-SPECIFIC FEATURES
    # =================================================

    features["bank_keyword_count"] = keyword_score(

        clean_text,

        BANK_KEYWORDS

    )

    features["upi_keyword_count"] = keyword_score(

        clean_text,

        UPI_KEYWORDS

    )

    features["urgency_score"] = keyword_score(

        clean_text,

        URGENCY_WORDS

    )

    features["threat_score"] = keyword_score(

        clean_text,

        THREAT_WORDS

    )

    features["verification_score"] = keyword_score(

        clean_text,

        VERIFY_WORDS

    )

    features["reward_score"] = keyword_score(

        clean_text,

        REWARD_WORDS

    )

    features["financial_score"] = keyword_score(

        clean_text,

        FINANCIAL_WORDS

    )

    features["government_score"] = keyword_score(

        clean_text,

        GOVERNMENT_WORDS

    )

    features["brand_score"] = keyword_score(

        clean_text,

        BRAND_WORDS

    )


    # =================================================
    # Rule Engine Features
    # =================================================

    features["rule_score"] = rule_result[
        "rule_score"
    ]

    features["matched_rules"] = rule_result[
        "matched_rules"
    ]

    features["matched_keywords"] = rule_result[
        "matched_keywords"
    ]


    # =================================================
    # Entity Engine Features
    # =================================================

    features["entity_count"] = entity_result[
        "entity_count"
    ]

    features["entities"] = entity_result[
        "entities"
    ]


    # =================================================
    # Return
    # =================================================

    return features


# =====================================================
# Direct Test
# =====================================================

if __name__ == "__main__":

    sms = input(
        "Enter SMS:\n\n"
    )

    result = extract_features(
        sms
    )

    print()
    print("=" * 60)
    print("SCAMSHIELD AI FEATURE EXTRACTION")
    print("=" * 60)

    print()

    print("Clean Text:")
    print(result["clean_text"])

    print()
    print("SCAM-SPECIFIC FEATURES")
    print("-" * 60)

    scam_features = [

        "bank_keyword_count",
        "upi_keyword_count",
        "urgency_score",
        "threat_score",
        "verification_score",
        "reward_score",
        "financial_score",
        "government_score",
        "brand_score"

    ]

    for name in scam_features:

        print(
            f"{name:30}: "
            f"{result[name]}"
        )