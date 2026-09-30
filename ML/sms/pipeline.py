"""
============================================================
ScamShield AI
SMS Prediction Pipeline
============================================================

This module:

1. Loads the trained SMS model
2. Loads Word TF-IDF vectorizer
3. Loads Character TF-IDF vectorizer
4. Loads numeric feature scaler
5. Extracts ScamShield features
6. Builds the final feature matrix
7. Predicts SCAM / LEGITIMATE
8. Returns explanation information

============================================================
"""

import os
import joblib
import numpy as np

from scipy.sparse import csr_matrix
from scipy.sparse import hstack

from .feature_builder import build_features


# ============================================================
# Paths
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(__file__)
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)


MODEL_PATH = os.path.join(
    MODEL_DIR,
    "sms_model.pkl"
)

WORD_VECTOR_PATH = os.path.join(
    MODEL_DIR,
    "word_vectorizer.pkl"
)

CHAR_VECTOR_PATH = os.path.join(
    MODEL_DIR,
    "char_vectorizer.pkl"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "scaler.pkl"
)


# ============================================================
# Load Models
# ============================================================

def load_models():

    print(
        "Loading ScamShield AI SMS models..."
    )

    model = joblib.load(
        MODEL_PATH
    )

    word_vectorizer = joblib.load(
        WORD_VECTOR_PATH
    )

    char_vectorizer = joblib.load(
        CHAR_VECTOR_PATH
    )

    scaler = joblib.load(
        SCALER_PATH
    )

    print(
        "Models loaded successfully."
    )

    return (
        model,
        word_vectorizer,
        char_vectorizer,
        scaler
    )


# ============================================================
# SMS Prediction Pipeline
# ============================================================

class SMSPipeline:

    def __init__(self):

        (
            self.model,
            self.word_vectorizer,
            self.char_vectorizer,
            self.scaler
        ) = load_models()


    # ========================================================
    # Prepare Features
    # ========================================================

    def prepare_features(self, text):

        # ----------------------------------------------------
        # ScamShield Feature Engineering
        # ----------------------------------------------------

        feature_result = build_features(
            text
        )

        clean_text = feature_result[
            "clean_text"
        ]

        numeric_features = feature_result[
            "numeric_features"
        ]


        # ----------------------------------------------------
        # Word TF-IDF
        # ----------------------------------------------------

        word_features = (
            self.word_vectorizer.transform(
                [clean_text]
            )
        )


        # ----------------------------------------------------
        # Character TF-IDF
        # ----------------------------------------------------

        char_features = (
            self.char_vectorizer.transform(
                [clean_text]
            )
        )


        # ----------------------------------------------------
        # Combine Text Features
        # ----------------------------------------------------

        text_features = hstack(
            [
                word_features,
                char_features
            ]
        )


        # ----------------------------------------------------
        # Numeric Features
        # ----------------------------------------------------

        numeric_array = np.array(
            [
                numeric_features
            ],
            dtype=float
        )


        numeric_scaled = (
            self.scaler.transform(
                numeric_array
            )
        )


        numeric_matrix = csr_matrix(
            numeric_scaled
        )


        # ----------------------------------------------------
        # Final Feature Matrix
        # ----------------------------------------------------

        final_features = hstack(
            [
                text_features,
                numeric_matrix
            ]
        )


        return (
            final_features,
            feature_result
        )


    # ========================================================
    # Predict SMS
    # ========================================================

    def predict(self, text):

        if not text or not str(text).strip():

            return {

                "prediction": "UNKNOWN",

                "label": "UNKNOWN",

                "confidence": 0.0,

                "risk": "UNKNOWN",

                "clean_text": "",

                "matched_keywords": [],

                "matched_rules": [],

                "entities": []

            }


        # ----------------------------------------------------
        # Prepare Features
        # ----------------------------------------------------

        final_features, feature_result = (
            self.prepare_features(text)
        )


        # ----------------------------------------------------
        # Model Prediction
        # ----------------------------------------------------

        prediction = self.model.predict(
            final_features
        )[0]


        # ----------------------------------------------------
        # Decision Score
        # ----------------------------------------------------

        decision_score = (
            self.model.decision_function(
                final_features
            )[0]
        )


        # ----------------------------------------------------
        # Approximate Confidence
        # ----------------------------------------------------

        confidence = (
            1 /
            (
                1 +
                np.exp(
                    -abs(
                        decision_score
                    )
                )
            )
        ) * 100


        confidence = round(
            float(confidence),
            2
        )


        # ----------------------------------------------------
        # Label
        # ----------------------------------------------------

        if prediction == "spam":

            label = "SCAM"

        else:

            label = "LEGITIMATE"


        # ----------------------------------------------------
        # Risk
        # ----------------------------------------------------

        if label == "SCAM":

            if confidence >= 80:

                risk = "HIGH"

            elif confidence >= 60:

                risk = "MEDIUM"

            else:

                risk = "LOW"

        else:

            risk = "SAFE"


        # ----------------------------------------------------
        # Return Result
        # ----------------------------------------------------

        return {

            "prediction": prediction,

            "label": label,

            "confidence": confidence,

            "risk": risk,

            "clean_text": feature_result[
                "clean_text"
            ],

            "matched_keywords": feature_result.get(
                "matched_keywords",
                []
            ),

            "matched_rules": feature_result.get(
                "matched_rules",
                []
            ),

            "entities": feature_result.get(
                "entities",
                []
            ),

            "bank_keyword_count": feature_result.get(
                "bank_keyword_count",
                0
            ),

            "upi_keyword_count": feature_result.get(
                "upi_keyword_count",
                0
            ),

            "urgency_score": feature_result.get(
                "urgency_score",
                0
            ),

            "threat_score": feature_result.get(
                "threat_score",
                0
            ),

            "verification_score": feature_result.get(
                "verification_score",
                0
            ),

            "reward_score": feature_result.get(
                "reward_score",
                0
            ),

            "financial_score": feature_result.get(
                "financial_score",
                0
            ),

            "government_score": feature_result.get(
                "government_score",
                0
            ),

            "brand_score": feature_result.get(
                "brand_score",
                0
            ),

            "rule_score": feature_result.get(
                "rule_score",
                0
            ),

            "entity_count": feature_result.get(
                "entity_count",
                0
            )

        }


# ============================================================
# Simple Function Interface
# ============================================================

_pipeline = None


def predict_sms(text):

    global _pipeline

    if _pipeline is None:

        _pipeline = SMSPipeline()

    return _pipeline.predict(
        text
    )


# ============================================================
# Testing
# ============================================================

if __name__ == "__main__":

    print()

    print(
        "=" * 70
    )

    print(
        "SCAMSHIELD AI SMS PIPELINE"
    )

    print(
        "=" * 70
    )

    print()


    sms = input(
        "Enter SMS:\n\n"
    )


    result = predict_sms(
        sms
    )


    print()

    print(
        "=" * 70
    )

    print(
        "PREDICTION RESULT"
    )

    print(
        "=" * 70
    )

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

    print(
        "Clean Text:"
    )

    print(
        result["clean_text"]
    )

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
        "Scam Features:"
    )

    print(
        "Bank Keywords       :",
        result["bank_keyword_count"]
    )

    print(
        "UPI Keywords        :",
        result["upi_keyword_count"]
    )

    print(
        "Urgency Score       :",
        result["urgency_score"]
    )

    print(
        "Threat Score        :",
        result["threat_score"]
    )

    print(
        "Verification Score  :",
        result["verification_score"]
    )

    print(
        "Reward Score        :",
        result["reward_score"]
    )

    print(
        "Financial Score     :",
        result["financial_score"]
    )

    print(
        "Government Score    :",
        result["government_score"]
    )

    print(
        "Brand Score         :",
        result["brand_score"]
    )

    print(
        "Rule Score          :",
        result["rule_score"]
    )

    print(
        "Entity Count        :",
        result["entity_count"]
    )

    print()

    print(
        "=" * 70
    )

    print(
        "PIPELINE TEST COMPLETED"
    )

    print(
        "=" * 70
    )