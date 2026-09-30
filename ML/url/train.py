"""
ScamShield AI
URL Model Training
"""

import os
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from ML.url.features import (
    build_features,
    FEATURE_NAMES
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "dataset",
    "url",
    "url_dataset.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "url_model.pkl"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "url_scaler.pkl"
)


# ============================================================
# SETTINGS
# ============================================================

TEST_SIZE = 0.20
RANDOM_STATE = 42


# ============================================================
# START
# ============================================================

print()
print("=" * 70)
print("SCAMSHIELD AI - URL MODEL TRAINING")
print("=" * 70)


# ============================================================
# LOAD DATASET
# ============================================================

print()
print("Loading URL dataset...")

df = pd.read_csv(
    DATASET_PATH
)

print()
print(
    "Original Dataset Shape:",
    df.shape
)


# ============================================================
# CHECK COLUMNS
# ============================================================

print()
print("Columns:")

print(
    df.columns.tolist()
)

if "url" not in df.columns:

    raise ValueError(
        "Dataset must contain a 'url' column."
    )

if "label" not in df.columns:

    raise ValueError(
        "Dataset must contain a 'label' column."
    )


# ============================================================
# KEEP REQUIRED COLUMNS
# ============================================================

df = df[
    [
        "url",
        "label"
    ]
].copy()


# ============================================================
# REMOVE EMPTY VALUES
# ============================================================

df.dropna(
    inplace=True
)

df["url"] = (
    df["url"]
    .astype(str)
    .str.strip()
)

df["label"] = (
    df["label"]
    .astype(str)
    .str.lower()
    .str.strip()
)


# ============================================================
# NORMALIZE LABELS
# ============================================================

def normalize_label(label):

    if label in {
        "legitimate",
        "legit",
        "safe",
        "benign",
        "good"
    }:

        return "legitimate"

    if label in {
        "phishing",
        "phish",
        "scam",
        "malicious",
        "bad"
    }:

        return "phishing"

    return None


df["label"] = df[
    "label"
].apply(
    normalize_label
)


# ============================================================
# REMOVE UNKNOWN LABELS
# ============================================================

before_labels = len(df)

df.dropna(
    subset=[
        "label"
    ],
    inplace=True
)

unknown_labels_removed = (
    before_labels -
    len(df)
)


# ============================================================
# REMOVE EMPTY URLS
# ============================================================

df = df[
    df["url"].str.len() > 0
]


# ============================================================
# REMOVE DUPLICATES
# ============================================================

before_duplicates = len(df)

df.drop_duplicates(
    subset=[
        "url"
    ],
    inplace=True
)

duplicates_removed = (
    before_duplicates -
    len(df)
)


# ============================================================
# DATASET INFORMATION
# ============================================================

print()
print("=" * 70)
print("DATASET CLEANING")
print("=" * 70)

print()

print(
    "Unknown Labels Removed:",
    unknown_labels_removed
)

print(
    "Duplicate URLs Removed:",
    duplicates_removed
)

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


# ============================================================
# FEATURE EXTRACTION
# ============================================================

print()
print("=" * 70)
print("EXTRACTING URL FEATURES")
print("=" * 70)

features_list = []

labels = []

total = len(df)

errors = 0

for index, row in enumerate(
    df.itertuples(
        index=False
    )
):

    url = row.url

    label = row.label

    try:

        result = build_features(
            url
        )

        features_list.append(
            result[
                "numeric_features"
            ]
        )

        labels.append(
            label
        )

    except Exception as error:

        errors += 1

        # Don't print every error
        # because large datasets can
        # contain unusual URLs.

        if errors <= 10:

            print()
            print(
                "Feature extraction error:"
            )

            print(
                url
            )

            print(
                error
            )

    # Progress

    if (
        (index + 1) % 5000 == 0
        or
        index + 1 == total
    ):

        print(
            f"Processed "
            f"{index + 1:,}"
            f"/"
            f"{total:,}"
        )


# ============================================================
# FEATURE MATRIX
# ============================================================

print()
print("=" * 70)
print("BUILDING FEATURE MATRIX")
print("=" * 70)

X = np.array(
    features_list,
    dtype=np.float64
)

y = np.array(
    labels
)

print()

print(
    "Feature Matrix Shape:",
    X.shape
)

print(
    "Number of Features:",
    len(FEATURE_NAMES)
)

print(
    "Extraction Errors:",
    errors
)


# ============================================================
# SAFETY CHECK
# ============================================================

if X.shape[1] != len(
    FEATURE_NAMES
):

    raise ValueError(
        "Feature count mismatch!"
    )


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

print()
print("=" * 70)
print("SPLITTING DATASET")
print("=" * 70)

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=TEST_SIZE,

    random_state=RANDOM_STATE,

    stratify=y
)

print()

print(
    "Training Samples:",
    len(X_train)
)

print(
    "Testing Samples:",
    len(X_test)
)


# ============================================================
# SCALE FEATURES
# ============================================================

print()
print("=" * 70)
print("SCALING FEATURES")
print("=" * 70)

scaler = StandardScaler()

X_train = scaler.fit_transform(
    X_train
)

X_test = scaler.transform(
    X_test
)

print()

print(
    "Feature Scaling Completed."
)


# ============================================================
# TRAIN MODEL
# ============================================================

print()
print("=" * 70)
print("TRAINING URL MODEL")
print("=" * 70)

print()

print(
    "Training Logistic Regression..."
)

model = LogisticRegression(

    max_iter=1000,

    class_weight="balanced",

    random_state=RANDOM_STATE,

    n_jobs=-1
)

model.fit(
    X_train,
    y_train
)

print()

print(
    "Training Completed."
)


# ============================================================
# PREDICTION
# ============================================================

print()
print("=" * 70)
print("PREDICTING TEST DATA")
print("=" * 70)

predictions = model.predict(
    X_test
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
    pos_label="phishing",
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    pos_label="phishing",
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    pos_label="phishing",
    zero_division=0
)


# ============================================================
# RESULTS
# ============================================================

print()
print("=" * 70)
print("URL MODEL RESULTS")
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
            "phishing"
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
        "phishing"
    ]
)

print()

print(
    "                  Predicted"
)

print(
    "               Legitimate  Phishing"
)

print(
    f"Actual Legitimate"
    f"      {matrix[0][0]:6d}"
    f"    {matrix[0][1]:6d}"
)

print(
    f"Actual Phishing"
    f"        {matrix[1][0]:6d}"
    f"    {matrix[1][1]:6d}"
)


# ============================================================
# SAVE MODEL
# ============================================================

print()
print("=" * 70)
print("SAVING URL MODEL")
print("=" * 70)

joblib.dump(
    model,
    MODEL_PATH
)

joblib.dump(
    scaler,
    SCALER_PATH
)


print()

print(
    "URL Model:",
    MODEL_PATH
)

print(
    "URL Scaler:",
    SCALER_PATH
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

print()
print("=" * 70)
print("URL FEATURE IMPORTANCE")
print("=" * 70)

coefficients = model.coef_[0]

feature_importance = sorted(

    zip(
        FEATURE_NAMES,
        coefficients
    ),

    key=lambda x: abs(x[1]),

    reverse=True
)

print()

for name, coefficient in (
    feature_importance[:20]
):

    print(
        f"{name:32}"
        f": {coefficient:.4f}"
    )


# ============================================================
# FINAL
# ============================================================

print()
print("=" * 70)
print(
    "URL MODEL TRAINING COMPLETED SUCCESSFULLY"
)
print("=" * 70)

print()

print(
    f"Final Accuracy : "
    f"{accuracy * 100:.2f}%"
)

print(
    f"Final Precision: "
    f"{precision * 100:.2f}%"
)

print(
    f"Final Recall   : "
    f"{recall * 100:.2f}%"
)

print(
    f"Final F1 Score : "
    f"{f1 * 100:.2f}%"
)

print()