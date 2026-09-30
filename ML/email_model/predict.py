"""
ScamShield AI
Email Prediction Engine

Reads a .eml file and predicts:
    SCAM
    LEGITIMATE

Uses:
    - Word TF-IDF
    - Character TF-IDF
    - Numeric engineered features
    - Trained SVM model
"""

import os
import joblib
import numpy as np

from scipy.sparse import csr_matrix, hstack
from email import policy
from email.parser import BytesParser

from ML.email_model.features import build_features


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "email_model.pkl"
)

WORD_VECTORIZER_PATH = os.path.join(
    MODEL_DIR,
    "email_word_vectorizer.pkl"
)

CHAR_VECTORIZER_PATH = os.path.join(
    MODEL_DIR,
    "email_char_vectorizer.pkl"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "email_scaler.pkl"
)


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading ScamShield AI Email Model...")

model = joblib.load(MODEL_PATH)

word_vectorizer = joblib.load(
    WORD_VECTORIZER_PATH
)

char_vectorizer = joblib.load(
    CHAR_VECTORIZER_PATH
)

scaler = joblib.load(
    SCALER_PATH
)

print("Email Model Loaded Successfully.")


# ============================================================
# READ .EML FILE
# ============================================================

def read_eml_file(file_path):
    """
    Reads an .eml file and extracts useful email information.
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

    # --------------------------------------------------------
    # Headers
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Extract body
    # --------------------------------------------------------

    plain_text = ""
    html_text = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            disposition = str(
                part.get(
                    "Content-Disposition",
                    ""
                )
            )

            # Ignore attachments
            if "attachment" in disposition:
                continue

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

            if content_type == "text/plain":

                plain_text += "\n" + str(
                    content
                )

            elif content_type == "text/html":

                html_text += "\n" + str(
                    content
                )

    else:

        try:

            content = message.get_content()

        except Exception:

            content = ""

        if message.get_content_type() == "text/plain":

            plain_text = str(
                content
            )

        elif message.get_content_type() == "text/html":

            html_text = str(
                content
            )

    # --------------------------------------------------------
    # Prefer plain text
    # --------------------------------------------------------

    body = plain_text.strip()

    if not body:

        body = html_text.strip()

    # --------------------------------------------------------
    # Build analysis text
    #
    # Subject is important for phishing detection.
    # --------------------------------------------------------

    analysis_text = (
        f"Subject: {subject}\n"
        f"{body}"
    ).strip()

    return {

        "sender": sender,

        "recipient": recipient,

        "reply_to": reply_to,

        "subject": subject,

        "date": date,

        "body": body,

        "analysis_text": analysis_text

    }


# ============================================================
# PREPARE FEATURES
# ============================================================

def prepare_features(text):

    # --------------------------------------------------------
    # Feature Engineering
    # --------------------------------------------------------

    features = build_features(
        text
    )

    clean_text = features[
        "clean_text"
    ]

    numeric_features = features[
        "numeric_features"
    ]

    # --------------------------------------------------------
    # Word TF-IDF
    # --------------------------------------------------------

    word_matrix = word_vectorizer.transform(
        [clean_text]
    )

    # --------------------------------------------------------
    # Character TF-IDF
    # --------------------------------------------------------

    char_matrix = char_vectorizer.transform(
        [clean_text]
    )

    # --------------------------------------------------------
    # Combine text features
    # --------------------------------------------------------

    text_matrix = hstack(
        [
            word_matrix,
            char_matrix
        ]
    )

    # --------------------------------------------------------
    # Numeric Features
    # --------------------------------------------------------

    numeric_array = np.array(
        [
            numeric_features
        ],
        dtype=float
    )

    numeric_array = scaler.transform(
        numeric_array
    )

    numeric_matrix = csr_matrix(
        numeric_array
    )

    # --------------------------------------------------------
    # Final feature matrix
    # --------------------------------------------------------

    final_features = hstack(
        [
            text_matrix,
            numeric_matrix
        ]
    )

    return (
        final_features,
        features
    )


# ============================================================
# PREDICT EMAIL
# ============================================================

def predict_email(file_path):

    # --------------------------------------------------------
    # Read email
    # --------------------------------------------------------

    email_data = read_eml_file(
        file_path
    )

    analysis_text = email_data[
        "analysis_text"
    ]

    if not analysis_text.strip():

        raise ValueError(
            "The email does not contain readable text."
        )

    # --------------------------------------------------------
    # Prepare features
    # --------------------------------------------------------

    final_features, features = prepare_features(
        analysis_text
    )

    # --------------------------------------------------------
    # Model prediction
    # --------------------------------------------------------

    prediction = model.predict(
        final_features
    )[0]

    # --------------------------------------------------------
    # Decision score
    # --------------------------------------------------------

    decision_score = model.decision_function(
        final_features
    )[0]

    # --------------------------------------------------------
    # Approximate confidence
    #
    # IMPORTANT:
    # This is a confidence-like score, not a calibrated
    # probability.
    # --------------------------------------------------------

    confidence = 1 / (
        1 + np.exp(
            -abs(
                float(decision_score)
            )
        )
    )

    confidence *= 100

    confidence = min(
        max(
            confidence,
            0
        ),
        100
    )

    # --------------------------------------------------------
    # Label
    # --------------------------------------------------------

    prediction_string = str(
        prediction
    ).lower()

    if prediction_string in {
        "spam",
        "scam",
        "phishing",
        "1"
    }:

        label = "SCAM"

    else:

        label = "LEGITIMATE"

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    if label == "SCAM":

        if confidence >= 80:
            risk = "HIGH"

        elif confidence >= 60:
            risk = "MEDIUM"

        else:
            risk = "LOW"

    else:

        if confidence < 60:
            risk = "REVIEW"

        else:
            risk = "SAFE"

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {

        "prediction": prediction,

        "label": label,

        "confidence": round(
            confidence,
            2
        ),

        "risk": risk,

        "sender": email_data[
            "sender"
        ],

        "recipient": email_data[
            "recipient"
        ],

        "reply_to": email_data[
            "reply_to"
        ],

        "subject": email_data[
            "subject"
        ],

        "date": email_data[
            "date"
        ],

        "body": email_data[
            "body"
        ],

        "clean_text": features[
            "clean_text"
        ],

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
        )

    }


# ============================================================
# COMMAND LINE TEST
# ============================================================

if __name__ == "__main__":

    print()

    print("=" * 70)
    print(
        "SCAMSHIELD AI - EMAIL SCAM DETECTOR"
    )
    print("=" * 70)

    print()

    file_path = input(
        "Enter .eml file path:\n\n"
    ).strip()

    try:

        result = predict_email(
            file_path
        )

        print()

        print("=" * 70)
        print(
            "EMAIL PREDICTION RESULT"
        )
        print("=" * 70)

        print()

        print(
            "Sender     :",
            result["sender"]
        )

        print(
            "Recipient  :",
            result["recipient"]
        )

        print(
            "Reply-To   :",
            result["reply_to"]
        )

        print(
            "Subject    :",
            result["subject"]
        )

        print(
            "Date       :",
            result["date"]
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
            "=" * 70
        )

        print(
            "EMAIL ANALYSIS COMPLETED"
        )

        print(
            "=" * 70
        )

    except Exception as error:

        print()

        print("=" * 70)
        print("ERROR")
        print("=" * 70)

        print()

        print(
            str(error)
        )