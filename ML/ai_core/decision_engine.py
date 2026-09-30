"""
====================================================
ScamShield AI
Decision Engine
====================================================
"""

from ML.ai_core.feature_engine import extract_features
from ML.ai_core.risk_engine import calculate_risk

def make_decision(risk_result, ml_prediction=None, ml_confidence=None):

    risk_score = risk_result["risk_score"]
    risk_level = risk_result["risk_level"]

    prediction = "LEGITIMATE"
    confidence = 100 - risk_score
    reason = "Low overall risk."

    # ------------------------------------------
    # Rule Based Decision
    # ------------------------------------------

    if risk_score >= 80:

        prediction = "SCAM"

        confidence = risk_score

        reason = "Critical risk score."

    elif risk_score >= 60:

        prediction = "SCAM"

        confidence = risk_score

        reason = "High risk score."

    elif risk_score >= 40:

        prediction = "SUSPICIOUS"

        confidence = risk_score

        reason = "Medium risk score."

    # ------------------------------------------
    # ML Override
    # ------------------------------------------

    if ml_prediction is not None:

        if ml_prediction.upper() == "SCAM":

            prediction = "SCAM"

            if ml_confidence is not None:

                confidence = max(

                    confidence,

                    round(ml_confidence * 100)

                )

            reason += " ML model also predicts scam."

    return {

        "prediction": prediction,

        "confidence": round(confidence),

        "reason": reason,

        "risk_score": risk_score,

        "risk_level": risk_level

    }


# ==========================================
# Testing
# ==========================================

if __name__ == "__main__":

    from feature_engine import extract_features
    from risk_engine import calculate_risk

    sms = input("Enter Message:\n\n")

    features = extract_features(sms)

    risk = calculate_risk(features)

    result = make_decision(risk)

    print()

    print("=" * 60)

    print("DECISION ENGINE")

    print("=" * 60)

    print()

    print("Prediction :", result["prediction"])

    print("Confidence :", result["confidence"], "%")

    print("Risk Score :", result["risk_score"])

    print("Risk Level :", result["risk_level"])

    print()

    print("Reason")

    print("------")

    print(result["reason"])