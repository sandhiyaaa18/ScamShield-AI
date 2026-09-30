"""
============================================================
ScamShield AI
SMS Feature Builder
============================================================
Builds the numeric and explanation features used by
the SMS detection model.
============================================================
"""

from ML.ai_core.feature_engine import extract_features


# ============================================================
# Build Features
# ============================================================

def build_features(text):

    # --------------------------------------------------------
    # Extract all features from Feature Engine
    # --------------------------------------------------------

    features = extract_features(text)


    # ========================================================
    # Numeric Features
    #
    # IMPORTANT:
    # Keep this order exactly the same as during training.
    # ========================================================

    numeric_features = [

        # ----------------------------------------------------
        # Basic Features
        # ----------------------------------------------------

        features["char_count"],
        features["word_count"],
        features["url_count"],
        features["email_count"],
        features["phone_count"],
        features["money_count"],
        features["number_count"],

        features["uppercase_ratio"],
        features["digit_ratio"],

        features["special_character_count"],
        features["repeated_character_count"],
        features["average_word_length"],


        # ----------------------------------------------------
        # Text Statistics
        # ----------------------------------------------------

        features["entropy"],
        features["token_count"],
        features["unique_tokens"],
        features["lexical_diversity"],


        # ----------------------------------------------------
        # Suspicious Language
        # ----------------------------------------------------

        features["suspicious_keyword_count"],
        features["financial_keyword_count"],
        features["action_keyword_count"],
        features["urgency_keyword_count"],


        # ----------------------------------------------------
        # Scam-Specific Features
        # ----------------------------------------------------

        features["bank_keyword_count"],
        features["upi_keyword_count"],
        features["urgency_score"],
        features["threat_score"],
        features["verification_score"],
        features["reward_score"],
        features["financial_score"],
        features["government_score"],
        features["brand_score"],


        # ----------------------------------------------------
        # Rule + Entity
        # ----------------------------------------------------

        features["rule_score"],
        features["entity_count"]

    ]


    # ========================================================
    # Feature Names
    # ========================================================

    feature_names = [

        # Basic

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


        # Text Statistics

        "entropy",
        "token_count",
        "unique_tokens",
        "lexical_diversity",


        # Suspicious Language

        "suspicious_keyword_count",
        "financial_keyword_count",
        "action_keyword_count",
        "urgency_keyword_count",


        # Scam-Specific

        "bank_keyword_count",
        "upi_keyword_count",
        "urgency_score",
        "threat_score",
        "verification_score",
        "reward_score",
        "financial_score",
        "government_score",
        "brand_score",


        # Rule + Entity

        "rule_score",
        "entity_count"

    ]


    # ========================================================
    # Return Everything
    # ========================================================
    #
    # IMPORTANT:
    # `return {` must be on the SAME line.
    # ========================================================

    return {

        # ----------------------------------------------------
        # Text
        # ----------------------------------------------------

        "clean_text": features.get(
            "clean_text",
            ""
        ),


        # ----------------------------------------------------
        # Model Features
        # ----------------------------------------------------

        "numeric_features": numeric_features,

        "feature_names": feature_names,


        # ----------------------------------------------------
        # Explanation Information
        # ----------------------------------------------------

        "matched_keywords": features.get(
            "matched_keywords",
            []
        ),

        "matched_rules": features.get(
            "matched_rules",
            []
        ),

        "entities": features.get(
            "entities",
            []
        ),


        # ----------------------------------------------------
        # Scam-Specific Information
        # ----------------------------------------------------

        "bank_keyword_count": features.get(
            "bank_keyword_count",
            0
        ),

        "upi_keyword_count": features.get(
            "upi_keyword_count",
            0
        ),

        "urgency_score": features.get(
            "urgency_score",
            0
        ),

        "threat_score": features.get(
            "threat_score",
            0
        ),

        "verification_score": features.get(
            "verification_score",
            0
        ),

        "reward_score": features.get(
            "reward_score",
            0
        ),

        "financial_score": features.get(
            "financial_score",
            0
        ),

        "government_score": features.get(
            "government_score",
            0
        ),

        "brand_score": features.get(
            "brand_score",
            0
        ),


        # ----------------------------------------------------
        # Rule + Entity
        # ----------------------------------------------------

        "rule_score": features.get(
            "rule_score",
            0
        ),

        "entity_count": features.get(
            "entity_count",
            0
        )

    }


# ============================================================
# Testing
# ============================================================

if __name__ == "__main__":

    sms = input(
        "SMS:\n\n"
    )


    result = build_features(
        sms
    )


    print(
        "\n" + "=" * 60
    )

    print(
        "SCAMSHIELD AI FEATURE BUILDER"
    )

    print(
        "=" * 60
    )


    # --------------------------------------------------------
    # Clean Text
    # --------------------------------------------------------

    print(
        "\nClean Text:\n"
    )

    print(
        result["clean_text"]
    )


    # --------------------------------------------------------
    # Numeric Features
    # --------------------------------------------------------

    print(
        "\nNumeric Features:\n"
    )


    for name, value in zip(

        result["feature_names"],

        result["numeric_features"]

    ):

        print(
            f"{name:30}: {value}"
        )


    # --------------------------------------------------------
    # Explanation
    # --------------------------------------------------------

    print(
        "\nMatched Keywords:\n"
    )

    print(
        result["matched_keywords"]
    )


    print(
        "\nMatched Rules:\n"
    )

    print(
        result["matched_rules"]
    )


    print(
        "\nEntities:\n"
    )

    print(
        result["entities"]
    )


    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print(
        "\nScam-Specific Scores:\n"
    )

    print(
        f"{'Bank Keywords':30}: "
        f"{result['bank_keyword_count']}"
    )

    print(
        f"{'UPI Keywords':30}: "
        f"{result['upi_keyword_count']}"
    )

    print(
        f"{'Urgency Score':30}: "
        f"{result['urgency_score']}"
    )

    print(
        f"{'Threat Score':30}: "
        f"{result['threat_score']}"
    )

    print(
        f"{'Verification Score':30}: "
        f"{result['verification_score']}"
    )

    print(
        f"{'Reward Score':30}: "
        f"{result['reward_score']}"
    )

    print(
        f"{'Financial Score':30}: "
        f"{result['financial_score']}"
    )

    print(
        f"{'Government Score':30}: "
        f"{result['government_score']}"
    )

    print(
        f"{'Brand Score':30}: "
        f"{result['brand_score']}"
    )

    print(
        f"{'Rule Score':30}: "
        f"{result['rule_score']}"
    )

    print(
        f"{'Entity Count':30}: "
        f"{result['entity_count']}"
    )


    print(
        "\n" + "=" * 60
    )

    print(
        "FEATURE EXTRACTION COMPLETED"
    )

    print(
        "=" * 60
    )