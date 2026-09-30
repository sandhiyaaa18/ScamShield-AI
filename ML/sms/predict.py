"""
============================================================
ScamShield AI
SMS Prediction Interface
============================================================

This file provides a simple interface for the rest of
ScamShield AI to predict an SMS.

The actual ML processing is handled by pipeline.py.

Usage:

    from sms.predict import predict_sms

    result = predict_sms(message)

============================================================
"""

from ML.sms.pipeline import predict_sms


# ============================================================
# Command Line Testing
# ============================================================

if __name__ == "__main__":

    print()

    print("=" * 70)
    print("SCAMSHIELD AI - SMS SCAM DETECTOR")
    print("=" * 70)

    print()

    sms = input(
        "Enter SMS:\n\n"
    )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    result = predict_sms(
        sms
    )

    # --------------------------------------------------------
    # Display Result
    # --------------------------------------------------------

    print()

    print("=" * 70)
    print("PREDICTION RESULT")
    print("=" * 70)

    print()

    print(
        "Prediction :",
        result["label"]
    )

    print(
        "Confidence :",
        result["confidence"],
        "%"
    )

    print(
        "Risk       :",
        result["risk"]
    )

    print()

    # --------------------------------------------------------
    # Clean Text
    # --------------------------------------------------------

    print(
        "Clean Text:"
    )

    print(
        result["clean_text"]
    )

    print()

    # --------------------------------------------------------
    # Matched Keywords
    # --------------------------------------------------------

    print(
        "Matched Keywords:"
    )

    print(
        result["matched_keywords"]
    )

    print()

    # --------------------------------------------------------
    # Matched Rules
    # --------------------------------------------------------

    print(
        "Matched Rules:"
    )

    print(
        result["matched_rules"]
    )

    print()

    # --------------------------------------------------------
    # Entities
    # --------------------------------------------------------

    print(
        "Entities:"
    )

    print(
        result["entities"]
    )

    print()

    # --------------------------------------------------------
    # Scam-Specific Features
    # --------------------------------------------------------

    print(
        "Scam Features:"
    )

    print(
        "Bank Keywords      :",
        result["bank_keyword_count"]
    )

    print(
        "UPI Keywords       :",
        result["upi_keyword_count"]
    )

    print(
        "Urgency Score      :",
        result["urgency_score"]
    )

    print(
        "Threat Score       :",
        result["threat_score"]
    )

    print(
        "Verification Score :",
        result["verification_score"]
    )

    print(
        "Reward Score       :",
        result["reward_score"]
    )

    print(
        "Financial Score    :",
        result["financial_score"]
    )

    print(
        "Government Score   :",
        result["government_score"]
    )

    print(
        "Brand Score        :",
        result["brand_score"]
    )

    print(
        "Rule Score         :",
        result["rule_score"]
    )

    print(
        "Entity Count       :",
        result["entity_count"]
    )

    print()

    print("=" * 70)
    print("PREDICTION COMPLETED")
    print("=" * 70)