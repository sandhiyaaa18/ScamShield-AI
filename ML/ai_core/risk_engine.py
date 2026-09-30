"""
====================================================
ScamShield AI
Risk Engine
====================================================
"""

from ML.ai_core.feature_engine import extract_features

def calculate_risk(features):

    score = 0

    reasons = []

    # ==========================================
    # Rule Engine
    # ==========================================

    rule_score = features["rule_score"]

    score += min(rule_score, 40)

    if rule_score > 0:
        reasons.append(
            f"Rule engine detected {len(features['matched_rules'])} suspicious patterns."
        )

    # ==========================================
    # Entity Engine
    # ==========================================

    entity_score = min(features["entity_count"] * 5, 20)

    score += entity_score

    if entity_score:
        reasons.append(
            f"{features['entity_count']} sensitive entities detected."
        )

    # ==========================================
    # URL
    # ==========================================

    if features["url_count"]:

        score += 15

        reasons.append("Contains URL.")

    # ==========================================
    # Email
    # ==========================================

    if features["email_count"]:

        score += 5

        reasons.append("Contains email address.")

    # ==========================================
    # Phone
    # ==========================================

    if features["phone_count"]:

        score += 5

        reasons.append("Contains phone number.")

    # ==========================================
    # Money
    # ==========================================

    if features["money_count"]:

        score += 10

        reasons.append("Contains money amount.")

    # ==========================================
    # Uppercase
    # ==========================================

    if features["uppercase_ratio"] > 0.30:

        score += 5

        reasons.append("Excessive uppercase usage.")

    # ==========================================
    # Repeated Characters
    # ==========================================

    if features["repeated_character_count"]:

        score += 5

        reasons.append("Repeated characters detected.")

    # ==========================================
    # Normalize
    # ==========================================

    score = min(score, 100)

    # ==========================================
    # Risk Level
    # ==========================================

    if score >= 80:

        level = "CRITICAL"

    elif score >= 60:

        level = "HIGH"

    elif score >= 35:

        level = "MEDIUM"

    else:

        level = "LOW"

    return {

        "risk_score": score,

        "risk_level": level,

        "reasons": reasons

    }


if __name__ == "__main__":

    from feature_engine import extract_features

    sms = input("Enter Message:\n\n")

    features = extract_features(sms)

    result = calculate_risk(features)

    print()

    print("=" * 60)

    print("RISK ENGINE")

    print("=" * 60)

    print()

    print("Risk Score :", result["risk_score"])

    print("Risk Level :", result["risk_level"])

    print()

    print("Reasons")

    print("-------")

    for reason in result["reasons"]:

        print("✓", reason)