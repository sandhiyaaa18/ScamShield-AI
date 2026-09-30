"""
ScamShield AI
Email Model Evaluation
"""

import os
import joblib
import numpy as np
import pandas as pd

from scipy.sparse import csr_matrix, hstack
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from ML.email_model.features import build_features


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

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "email_model.pkl"
)

WORD_PATH = os.path.join(
    MODEL_DIR,
    "email_word_vectorizer.pkl"
)

CHAR_PATH = os.path.join(
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

print()
print("=" * 70)
print("SCAMSHIELD AI - EMAIL MODEL EVALUATION")
print("=" * 70)

print()
print("Loading saved model...")

model = joblib.load(MODEL_PATH)
word_vectorizer = joblib.load(WORD_PATH)
char_vectorizer = joblib.load(CHAR_PATH)
scaler = joblib.load(SCALER_PATH)

print("Model loaded successfully.")


# ============================================================
# LOAD DATASET
# ============================================================

print()
print("=" * 70)
print("LOADING DATASET")
print("=" * 70)

df = pd.read_csv(DATASET_PATH)

print()
print("Dataset shape:", df.shape)

print()
print("Columns:")
print(df.columns.tolist())


# ============================================================
# CLEAN DATA
# ============================================================

df = df.dropna(
    subset=["text", "label"]
).copy()

df["text"] = df["text"].astype(str)
df["label"] = df["label"].astype(str).str.lower().str.strip()


# ============================================================
# REMOVE INVALID LABELS
# ============================================================

df = df[
    df["label"].isin(
        ["scam", "legitimate"]
    )
].copy()


print()
print("Class Distribution:")
print(df["label"].value_counts())


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X = df["text"]
y = df["label"]


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print()
print("=" * 70)
print("TEST DATA")
print("=" * 70)

print()
print("Training samples:", len(X_train))
print("Testing samples :", len(X_test))


# ============================================================
# FEATURE EXTRACTION
# ============================================================

print()
print("=" * 70)
print("EXTRACTING TEST FEATURES")
print("=" * 70)

clean_texts = []
numeric_features = []

total = len(X_test)

for i, text in enumerate(X_test):

    try:

        features = build_features(text)

        clean_texts.append(
            features["clean_text"]
        )

        numeric_features.append(
            features["numeric_features"]
        )

    except Exception as e:

        print()
        print("Feature extraction error:")
        print(e)

        clean_texts.append(text)
        numeric_features.append(
            [0] * 31
        )

    if (i + 1) % 500 == 0:
        print(
            f"Processed {i + 1}/{total}"
        )


# ============================================================
# WORD TF-IDF
# ============================================================

print()
print("Creating word TF-IDF features...")

word_matrix = word_vectorizer.transform(
    clean_texts
)


# ============================================================
# CHARACTER TF-IDF
# ============================================================

print()
print("Creating character TF-IDF features...")

char_matrix = char_vectorizer.transform(
    clean_texts
)


# ============================================================
# COMBINE TEXT FEATURES
# ============================================================

text_matrix = hstack(
    [
        word_matrix,
        char_matrix
    ]
)


# ============================================================
# NUMERIC FEATURES
# ============================================================

print()
print("Scaling numeric features...")

numeric_array = np.array(
    numeric_features,
    dtype=float
)

numeric_array = scaler.transform(
    numeric_array
)

numeric_matrix = csr_matrix(
    numeric_array
)


# ============================================================
# FINAL FEATURES
# ============================================================

final_features = hstack(
    [
        text_matrix,
        numeric_matrix
    ]
)


print()
print(
    "Final feature matrix shape:",
    final_features.shape
)


# ============================================================
# PREDICTION
# ============================================================

print()
print("=" * 70)
print("RUNNING MODEL EVALUATION")
print("=" * 70)

predictions = model.predict(
    final_features
)


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    pos_label="scam",
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    pos_label="scam",
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    pos_label="scam",
    zero_division=0
)


# ============================================================
# RESULTS
# ============================================================

print()
print("=" * 70)
print("EMAIL MODEL RESULTS")
print("=" * 70)

print()

print(
    f"Accuracy  : {accuracy * 100:.2f}%"
)

print(
    f"Precision : {precision * 100:.2f}%"
)

print(
    f"Recall    : {recall * 100:.2f}%"
)

print(
    f"F1 Score  : {f1 * 100:.2f}%"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print()
print("=" * 70)
print("CLASSIFICATION REPORT")
print("=" * 70)

print()

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


# ============================================================
# CONFUSION MATRIX
# ============================================================

print()
print("=" * 70)
print("CONFUSION MATRIX")
print("=" * 70)

matrix = confusion_matrix(
    y_test,
    predictions,
    labels=[
        "legitimate",
        "scam"
    ]
)

print()

print(
    "                 Predicted"
)

print(
    "              Legitimate  Scam"
)

print(
    f"Actual Legitimate   {matrix[0][0]:5d}   {matrix[0][1]:5d}"
)

print(
    f"Actual Scam         {matrix[1][0]:5d}   {matrix[1][1]:5d}"
)


# ============================================================
# FINAL
# ============================================================

print()
print("=" * 70)
print("EMAIL MODEL EVALUATION COMPLETED")
print("=" * 70)