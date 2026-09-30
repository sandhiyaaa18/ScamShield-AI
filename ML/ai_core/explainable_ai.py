"""
====================================================
ScamShield AI
Explainable AI Engine
====================================================
"""

import json
import os

from ML.ai_core.feature_engine import extract_features
from ML.ai_core.risk_engine import calculate_risk
from ML.ai_core.decision_engine import make_decision

BASE_DIR = os.path.dirname(__file__)

PREVENTION_FILE = os.path.join(
    BASE_DIR,
    "..",
    "knowledge_base",
    "prevention.json"
)


if os.path.exists(PREVENTION_FILE):

    with open(PREVENTION_FILE, "r", encoding="utf-8") as f:

        PREVENTION = json.load(f)

else:

    PREVENTION = {}


def generate_report(

    original_text,

    features,

    risk,

    decision

):

    matched_entities = []

    for entity_type, values in features["entities"].items():

        matched_entities.extend(values)

    prediction = decision["prediction"]

    if prediction == "SCAM":

        tips = PREVENTION.get(

            "SCAM",

            [

                "Do not click suspicious links.",

                "Never share OTP or passwords.",

                "Contact the organization through official channels."

            ]

        )

    elif prediction == "SUSPICIOUS":

        tips = PREVENTION.get(

            "SUSPICIOUS",

            [

                "Verify the sender before responding.",

                "Avoid sharing personal information."

            ]

        )

    else:

        tips = PREVENTION.get(

            "LEGITIMATE",

            [

                "No immediate action required."

            ]

        )

    report = {

        "prediction":

            prediction,

        "confidence":

            decision["confidence"],

        "risk_score":

            risk["risk_score"],

        "risk_level":

            risk["risk_level"],

        "reason":

            decision["reason"],

        "matched_rules":

            features["matched_rules"],

        "matched_keywords":

            features["matched_keywords"],

        "matched_entities":

            matched_entities,

        "statistics":

            features,

        "prevention":

            tips,

        "original_message":

            original_text

    }

    return report


if __name__ == "__main__":

    from feature_engine import extract_features
    from risk_engine import calculate_risk
    from decision_engine import make_decision

    sms = input("Enter Message:\n\n")

    features = extract_features(sms)

    risk = calculate_risk(features)

    decision = make_decision(risk)

    report = generate_report(

        sms,

        features,

        risk,

        decision

    )

    print()

    print("=" * 70)

    print("SCAMSHIELD AI REPORT")

    print("=" * 70)

    print()

    print("Prediction :", report["prediction"])

    print("Confidence :", report["confidence"], "%")

    print("Risk Level :", report["risk_level"])

    print("Risk Score :", report["risk_score"])

    print()

    print("Matched Rules")

    print("----------------")

    for rule in report["matched_rules"]:

        print("✓", rule)

    print()

    print("Matched Entities")

    print("----------------")

    for entity in report["matched_entities"]:

        print("✓", entity)

    print()

    print("Safety Tips")

    print("----------------")

    for tip in report["prevention"]:

        print("•", tip)