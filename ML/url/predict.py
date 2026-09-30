"""
ScamShield AI
URL Prediction Engine
"""

import os
import joblib

from ML.url.features import build_features


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "url_model.pkl"
)

SCALER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "url_scaler.pkl"
)


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    if not os.path.exists(MODEL_PATH):

        raise FileNotFoundError(
            f"URL model not found:\n{MODEL_PATH}"
        )

    if not os.path.exists(SCALER_PATH):

        raise FileNotFoundError(
            f"URL scaler not found:\n{SCALER_PATH}"
        )

    model = joblib.load(
        MODEL_PATH
    )

    scaler = joblib.load(
        SCALER_PATH
    )

    return model, scaler


# ============================================================
# STRONG SUSPICIOUS INDICATORS
# ============================================================

def has_strong_suspicious_indicators(result):

    """
    Check for structural URL indicators that are strong
    enough to prevent a trusted-domain override.

    Normal words such as login, account, secure, verify, etc.
    are NOT treated as strong indicators here because legitimate
    websites commonly use them.
    """

    feature_names = result.get(
        "feature_names",
        []
    )

    numeric_features = result.get(
        "numeric_features",
        []
    )

    if not feature_names or not numeric_features:
        return False

    feature_map = dict(
        zip(
            feature_names,
            numeric_features
        )
    )

    strong_indicators = [

        # URL uses an IP address instead of a normal domain
        feature_map.get(
            "ip_address",
            0
        ) == 1,

        # URL shortener
        feature_map.get(
            "is_shortened",
            0
        ) == 1,

        # Suspicious TLD
        feature_map.get(
            "suspicious_tld",
            0
        ) == 1,

        # @ symbol can hide the real destination
        feature_map.get(
            "has_at_symbol",
            0
        ) == 1,

        # Unusual port
        feature_map.get(
            "has_port",
            0
        ) == 1,

        # Too many subdomains
        feature_map.get(
            "many_subdomains",
            0
        ) == 1,

        # Suspicious double slash inside path
        feature_map.get(
            "has_double_slash_path",
            0
        ) == 1,
    ]

    return any(
        strong_indicators
    )


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(
    prediction,
    confidence,
    trusted_domain,
    strong_suspicious
):

    # --------------------------------------------------------
    # Trusted domain
    # --------------------------------------------------------

    if trusted_domain:

        # Trusted domain with strong structural indicators
        # should remain under review.
        if strong_suspicious:

            return "REVIEW"

        # Trusted domain without strong suspicious indicators
        if prediction == "legitimate":

            return "SAFE"

        # ML says phishing but trusted-domain rule says
        # there is not enough evidence to call it HIGH risk.
        return "REVIEW"


    # --------------------------------------------------------
    # Normal ML risk calculation
    # --------------------------------------------------------

    if prediction == "phishing":

        if confidence >= 90:

            return "HIGH"

        elif confidence >= 70:

            return "MEDIUM"

        else:

            return "LOW"


    else:

        if confidence >= 90:

            return "SAFE"

        elif confidence >= 70:

            return "LOW"

        else:

            return "MEDIUM"


# ============================================================
# PREDICT URL
# ============================================================

def predict_url(url):

    model, scaler = load_model()

    # --------------------------------------------------------
    # Extract URL features
    # --------------------------------------------------------

    result = build_features(
        url
    )

    numeric_features = [
        result[
            "numeric_features"
        ]
    ]

    # --------------------------------------------------------
    # Verify feature count
    # --------------------------------------------------------

    expected_features = (
        model.n_features_in_
    )

    actual_features = len(
        numeric_features[0]
    )

    if actual_features != expected_features:

        raise ValueError(
            "Feature count mismatch.\n"
            f"Model expects: "
            f"{expected_features}\n"
            f"Features provided: "
            f"{actual_features}"
        )

    # --------------------------------------------------------
    # Scale
    # --------------------------------------------------------

    scaled_features = scaler.transform(
        numeric_features
    )

    # --------------------------------------------------------
    # Original ML Prediction
    # --------------------------------------------------------

    ml_prediction = model.predict(
        scaled_features
    )[0]

    # --------------------------------------------------------
    # Probability
    # --------------------------------------------------------

    probabilities = (
        model.predict_proba(
            scaled_features
        )[0]
    )

    class_probabilities = dict(
        zip(
            model.classes_,
            probabilities
        )
    )

    ml_confidence = round(
        class_probabilities[
            ml_prediction
        ] * 100,
        2
    )

    # --------------------------------------------------------
    # Trusted Domain
    # --------------------------------------------------------

    trusted_domain = bool(
        result[
            "trusted_domain"
        ]
    )

    # --------------------------------------------------------
    # Strong Suspicious Indicators
    # --------------------------------------------------------

    strong_suspicious = (
        has_strong_suspicious_indicators(
            result
        )
    )

    # --------------------------------------------------------
    # FINAL DECISION
    # --------------------------------------------------------

    prediction = ml_prediction
    confidence = ml_confidence
    decision_source = "ML Model"

    # --------------------------------------------------------
    # TRUSTED DOMAIN OVERRIDE
    # --------------------------------------------------------

    if (
        trusted_domain
        and not strong_suspicious
    ):

        # A trusted domain with no strong structural
        # suspicious indicators is treated as legitimate.

        prediction = "legitimate"

        confidence = 100.0

        decision_source = (
            "Trusted Domain Rule"
        )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    risk = get_risk_level(

        prediction,

        confidence,

        trusted_domain,

        strong_suspicious
    )

    # --------------------------------------------------------
    # Return
    # --------------------------------------------------------

    return {

        "url":
            result[
                "clean_url"
            ],

        "prediction":
            prediction,

        "confidence":
            confidence,

        "risk":
            risk,

        "trusted_domain":
            trusted_domain,

        "matched_keywords":
            result[
                "matched_keywords"
            ],

        "matched_tld":
            result[
                "matched_tld"
            ],

        "decision_source":
            decision_source,

        "ml_prediction":
            ml_prediction,

        "ml_confidence":
            ml_confidence,

        "strong_suspicious_indicators":
            strong_suspicious
    }


# ============================================================
# DISPLAY RESULT
# ============================================================

def display_result(result):

    print()

    print("=" * 70)

    print(
        "SCAMSHIELD AI - URL SCAM DETECTOR"
    )

    print("=" * 70)

    print()

    print(
        "URL:"
    )

    print(
        result["url"]
    )

    print()

    print(
        "Prediction :",
        result[
            "prediction"
        ].upper()
    )

    print(
        "Confidence :",
        f"{result['confidence']:.2f}%"
    )

    print(
        "Risk       :",
        result[
            "risk"
        ]
    )

    print(
        "Trusted Domain:",
        "YES"
        if result[
            "trusted_domain"
        ]
        else "NO"
    )

    print(
        "Decision Source:",
        result[
            "decision_source"
        ]
    )

    print(
        "ML Prediction:",
        result[
            "ml_prediction"
        ].upper()
    )

    print(
        "ML Confidence:",
        f"{result['ml_confidence']:.2f}%"
    )

    print()

    print(
        "Strong Suspicious Indicators:",
        "YES"
        if result[
            "strong_suspicious_indicators"
        ]
        else "NO"
    )

    print()

    print(
        "Matched Suspicious Keywords:"
    )

    if result[
        "matched_keywords"
    ]:

        print(
            ", ".join(
                result[
                    "matched_keywords"
                ]
            )
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

    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()

    print("=" * 70)

    print(
        "SCAMSHIELD AI - URL PREDICTION"
    )

    print("=" * 70)

    print()

    url = input(
        "Enter URL: "
    ).strip()

    if not url:

        print()

        print(
            "ERROR: URL cannot be empty."
        )

    else:

        try:

            result = predict_url(
                url
            )

            display_result(
                result
            )

        except Exception as error:

            print()

            print("=" * 70)

            print(
                "ERROR"
            )

            print("=" * 70)

            print()

            print(
                error
            )