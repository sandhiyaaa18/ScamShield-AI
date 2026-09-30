"""
============================================================
ScamShield AI
Email Scam Detection - Model Training
============================================================

Training pipeline:

    Email Dataset
          ↓
    Clean / Normalize Labels
          ↓
    Email Feature Extraction
          ↓
    Word TF-IDF
          +
    Character TF-IDF
          +
    Numeric Features
          ↓
    SVM Classifier
          ↓
    Saved Model
============================================================
"""

import os
import re
import warnings

import joblib
import numpy as np
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from ML.email_model.features import build_features


warnings.filterwarnings("ignore")


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "dataset",
    "email",
    "scamshield_email_combined_cleaned.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

os.makedirs(
    MODEL_DIR,
    exist_ok=True
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

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "email_model.pkl"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

TEST_SIZE = 0.20


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def normalize_label(label):
    """
    Convert different dataset label formats into:

        scam
        legitimate
    """

    if pd.isna(label):
        return None

    value = str(label).strip().lower()

    # --------------------------------------------------------
    # Scam / phishing labels
    # --------------------------------------------------------

    scam_labels = {
        "scam",
        "spam",
        "phishing",
        "fraud",
        "malicious",
        "suspicious",
        "1",
        "true"
    }

    if value in scam_labels:
        return "scam"

    # --------------------------------------------------------
    # Legitimate labels
    # --------------------------------------------------------

    legitimate_labels = {
        "legitimate",
        "legit",
        "ham",
        "safe",
        "normal",
        "benign",
        "0",
        "false"
    }

    if value in legitimate_labels:
        return "legitimate"

    # --------------------------------------------------------
    # Partial matching
    # --------------------------------------------------------

    if any(
        word in value
        for word in [
            "phish",
            "scam",
            "fraud",
            "malicious",
            "spam"
        ]
    ):
        return "scam"

    if any(
        word in value
        for word in [
            "legit",
            "ham",
            "safe",
            "benign",
            "normal"
        ]
    ):
        return "legitimate"

    return None


# ============================================================
# FIND DATASET COLUMNS
# ============================================================

def find_columns(df):
    """
    Automatically find text and label columns.
    """

    columns = [
        str(column).strip()
        for column in df.columns
    ]

    lower_columns = {
        column.lower(): column
        for column in columns
    }

    # --------------------------------------------------------
    # Possible label columns
    # --------------------------------------------------------

    label_candidates = [
        "label",
        "labels",
        "class",
        "category",
        "target",
        "type",
        "classification"
    ]

    label_column = None

    for candidate in label_candidates:

        if candidate in lower_columns:

            label_column = lower_columns[candidate]

            break

    # --------------------------------------------------------
    # Possible text columns
    # --------------------------------------------------------

    text_candidates = [
        "text",
        "email",
        "body",
        "message",
        "content",
        "email_text",
        "mail"
    ]

    text_column = None

    for candidate in text_candidates:

        if candidate in lower_columns:

            text_column = lower_columns[candidate]

            break

    # --------------------------------------------------------
    # If label column wasn't found
    # try columns containing label/category
    # --------------------------------------------------------

    if label_column is None:

        for column in columns:

            name = column.lower()

            if (
                "label" in name
                or "class" in name
                or "category" in name
                or "target" in name
            ):

                label_column = column

                break

    # --------------------------------------------------------
    # If text column wasn't found
    # choose the longest text-like column
    # --------------------------------------------------------

    if text_column is None:

        candidates = []

        for column in columns:

            if column == label_column:
                continue

            try:

                average_length = (
                    df[column]
                    .fillna("")
                    .astype(str)
                    .str.len()
                    .mean()
                )

                candidates.append(
                    (
                        column,
                        average_length
                    )
                )

            except Exception:
                pass

        if candidates:

            candidates.sort(
                key=lambda x: x[1],
                reverse=True
            )

            text_column = candidates[0][0]

    return text_column, label_column


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    print()
    print("=" * 70)
    print("LOADING EMAIL DATASET")
    print("=" * 70)

    print()
    print("Dataset:")
    print(DATASET_PATH)

    if not os.path.exists(DATASET_PATH):

        raise FileNotFoundError(
            f"\nDataset not found:\n{DATASET_PATH}"
        )

    df = pd.read_csv(
        DATASET_PATH
    )

    print()
    print(
        "Original Shape:",
        df.shape
    )

    print()
    print(
        "Columns:"
    )

    print(
        list(df.columns)
    )

    # --------------------------------------------------------
    # Find columns
    # --------------------------------------------------------

    text_column, label_column = find_columns(
        df
    )

    if text_column is None:

        raise ValueError(
            "\nCould not find email/text column."
        )

    if label_column is None:

        raise ValueError(
            "\nCould not find label column."
        )

    print()
    print(
        "Detected Text Column :",
        text_column
    )

    print(
        "Detected Label Column:",
        label_column
    )

    # --------------------------------------------------------
    # Keep only required columns
    # --------------------------------------------------------

    df = df[
        [
            text_column,
            label_column
        ]
    ].copy()

    df.columns = [
        "text",
        "label"
    ]

    # --------------------------------------------------------
    # Remove empty values
    # --------------------------------------------------------

    df["text"] = (
        df["text"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    df["label"] = (
        df["label"]
        .apply(normalize_label)
    )

    df = df[
        df["text"].str.len() > 0
    ]

    df = df[
        df["label"].notna()
    ]

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    before = len(df)

    df = df.drop_duplicates(
        subset=["text", "label"]
    )

    after = len(df)

    print()
    print(
        "Duplicate Rows Removed:",
        before - after
    )

    # --------------------------------------------------------
    # Final dataset
    # --------------------------------------------------------

    print()
    print(
        "Clean Dataset Shape:",
        df.shape
    )

    print()
    print(
        "Class Distribution:"
    )

    print(
        df["label"].value_counts()
    )

    # --------------------------------------------------------
    # Make sure both classes exist
    # --------------------------------------------------------

    classes = set(
        df["label"].unique()
    )

    required_classes = {
        "scam",
        "legitimate"
    }

    if not required_classes.issubset(classes):

        raise ValueError(
            "\nDataset must contain BOTH:\n"
            "  scam\n"
            "  legitimate\n\n"
            f"Found: {classes}"
        )

    return df


# ============================================================
# BUILD NUMERIC FEATURES
# ============================================================

def extract_numeric_features(texts):

    print()
    print("=" * 70)
    print("EXTRACTING EMAIL FEATURES")
    print("=" * 70)

    numeric_features = []

    valid_indices = []

    for index, text in enumerate(texts):

        try:

            result = build_features(
                text
            )

            values = result.get(
                "numeric_features"
            )

            if values is None:

                raise ValueError(
                    "build_features() did not "
                    "return numeric_features"
                )

            numeric_features.append(
                values
            )

            valid_indices.append(
                index
            )

        except Exception as error:

            print(
                f"\nWarning: Feature extraction "
                f"failed for row {index}"
            )

            print(
                error
            )

    if not numeric_features:

        raise ValueError(
            "\nNo numeric features were extracted."
        )

    print()
    print(
        "Feature Extraction Completed."
    )

    print(
        "Numeric Feature Count:",
        len(numeric_features[0])
    )

    return (
        np.asarray(
            numeric_features,
            dtype=float
        ),
        valid_indices
    )


# ============================================================
# MAIN TRAINING
# ============================================================

def train():

    print()
    print("=" * 70)
    print("SCAMSHIELD AI - EMAIL MODEL TRAINING")
    print("=" * 70)

    # ========================================================
    # Load Dataset
    # ========================================================

    df = load_dataset()

    texts = df[
        "text"
    ].tolist()

    labels = df[
        "label"
    ].values

    # ========================================================
    # Feature Extraction
    # ========================================================

    numeric_array, valid_indices = (
        extract_numeric_features(
            texts
        )
    )

    # --------------------------------------------------------
    # Keep only successfully processed rows
    # --------------------------------------------------------

    texts = [
        texts[i]
        for i in valid_indices
    ]

    labels = [
        labels[i]
        for i in valid_indices
    ]

    labels = np.asarray(
        labels
    )

    # ========================================================
    # WORD TF-IDF
    # ========================================================

    print()
    print("=" * 70)
    print("BUILDING WORD TF-IDF")
    print("=" * 70)

    word_vectorizer = TfidfVectorizer(

        lowercase=True,

        strip_accents="unicode",

        ngram_range=(
            1,
            2
        ),

        min_df=2,

        max_df=0.98,

        sublinear_tf=True,

        max_features=100000
    )

    word_matrix = (
        word_vectorizer.fit_transform(
            texts
        )
    )

    print()
    print(
        "Word Matrix:",
        word_matrix.shape
    )

    # ========================================================
    # CHARACTER TF-IDF
    # ========================================================

    print()
    print("=" * 70)
    print("BUILDING CHARACTER TF-IDF")
    print("=" * 70)

    char_vectorizer = TfidfVectorizer(

        analyzer="char",

        lowercase=True,

        ngram_range=(
            3,
            5
        ),

        min_df=2,

        sublinear_tf=True,

        max_features=100000
    )

    char_matrix = (
        char_vectorizer.fit_transform(
            texts
        )
    )

    print()
    print(
        "Character Matrix:",
        char_matrix.shape
    )

    # ========================================================
    # SCALE NUMERIC FEATURES
    # ========================================================

    print()
    print("=" * 70)
    print("SCALING NUMERIC FEATURES")
    print("=" * 70)

    scaler = StandardScaler()

    numeric_scaled = (
        scaler.fit_transform(
            numeric_array
        )
    )

    numeric_matrix = csr_matrix(
        numeric_scaled
    )

    print()
    print(
        "Numeric Matrix:",
        numeric_matrix.shape
    )

    # ========================================================
    # COMBINE FEATURES
    # ========================================================

    print()
    print("=" * 70)
    print("COMBINING FEATURES")
    print("=" * 70)

    X = hstack(
        [
            word_matrix,
            char_matrix,
            numeric_matrix
        ],
        format="csr"
    )

    y = labels

    print()
    print(
        "Final Feature Matrix:",
        X.shape
    )

    print()
    print(
        "Training Samples:",
        X.shape[0]
    )

    print(
        "Total Features:",
        X.shape[1]
    )

    # ========================================================
    # TRAIN / TEST SPLIT
    # ========================================================

    print()
    print("=" * 70)
    print("SPLITTING DATASET")
    print("=" * 70)

    X_train, X_test, y_train, y_test = (
        train_test_split(

            X,
            y,

            test_size=TEST_SIZE,

            random_state=RANDOM_STATE,

            stratify=y
        )
    )

    print()
    print(
        "Training Shape:",
        X_train.shape
    )

    print(
        "Testing Shape:",
        X_test.shape
    )

    # ========================================================
    # TRAIN SVM
    # ========================================================

    print()
    print("=" * 70)
    print("TRAINING EMAIL SVM")
    print("=" * 70)

    model = LinearSVC(

        C=1.5,

        class_weight="balanced",

        max_iter=5000,

        random_state=RANDOM_STATE
    )

    model.fit(
        X_train,
        y_train
    )

    print()
    print(
        "EMAIL SVM TRAINING COMPLETED"
    )

    # ========================================================
    # EVALUATION
    # ========================================================

    print()
    print("=" * 70)
    print("EVALUATING EMAIL MODEL")
    print("=" * 70)

    predictions = model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print()
    print(
        f"Accuracy: {accuracy * 100:.2f}%"
    )

    print()
    print(
        "Classification Report:"
    )

    print(
        classification_report(
            y_test,
            predictions,
            labels=[
                "legitimate",
                "scam"
            ],
            zero_division=0
        )
    )

    print(
        "Confusion Matrix:"
    )

    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=[
                "legitimate",
                "scam"
            ]
        )
    )

    # ========================================================
    # SAVE MODEL
    # ========================================================

    print()
    print("=" * 70)
    print("SAVING EMAIL MODEL")
    print("=" * 70)

    joblib.dump(
        model,
        MODEL_PATH
    )

    joblib.dump(
        word_vectorizer,
        WORD_VECTORIZER_PATH
    )

    joblib.dump(
        char_vectorizer,
        CHAR_VECTORIZER_PATH
    )

    joblib.dump(
        scaler,
        SCALER_PATH
    )

    print()
    print(
        "Saved:"
    )

    print(
        MODEL_PATH
    )

    print(
        WORD_VECTORIZER_PATH
    )

    print(
        CHAR_VECTORIZER_PATH
    )

    print(
        SCALER_PATH
    )

    # ========================================================
    # COMPLETE
    # ========================================================

    print()
    print("=" * 70)
    print("EMAIL MODEL TRAINING COMPLETED")
    print("=" * 70)

    print()
    print(
        f"Final Accuracy: {accuracy * 100:.2f}%"
    )

    print()
    print(
        "Model is ready for prediction."
    )

    print(
        "=" * 70
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    train()