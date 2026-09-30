"""
=========================================================
ScamShield AI
SMS Model Training Pipeline
=========================================================
"""

import os
import joblib
import numpy as np
import pandas as pd

from scipy.sparse import csr_matrix
from scipy.sparse import hstack

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

from sms.config import *

from sms.vectorizer import (
    fit_vectorizers,
    transform,
    word_vectorizer,
    char_vectorizer
)

from sms.feature_builder import build_features
from sms.ensemble import build_models


# ====================================================
# Paths
# ====================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(__file__)
)


DATASET_PATH = os.path.join(
    BASE_DIR,
    "dataset",
    "sms",
    "sms_dataset_cleaned.csv"
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
    "sms_model.pkl"
)

WORD_PATH = os.path.join(
    MODEL_DIR,
    "word_vectorizer.pkl"
)

CHAR_PATH = os.path.join(
    MODEL_DIR,
    "char_vectorizer.pkl"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "scaler.pkl"
)


# ====================================================
# Load Dataset
# ====================================================

print()
print("=" * 60)
print("Loading SMS Dataset...")
print("=" * 60)

df = pd.read_csv(
    DATASET_PATH
)

df.dropna(
    inplace=True
)

df["message"] = df["message"].astype(str)

df["label"] = df["label"].astype(str)


print()

print(
    "Dataset Shape :",
    df.shape
)

print()

print(
    df["label"].value_counts()
)

print()


# ====================================================
# AI Feature Extraction
# ====================================================

print("=" * 60)
print("Building AI Features...")
print("=" * 60)

texts = []

original_messages = []

numeric_features = []

labels = []

total = len(df)


for index, row in df.iterrows():

    feature = build_features(
        row["message"]
    )


    texts.append(
        feature["clean_text"]
    )


    original_messages.append(
        row["message"]
    )


    numeric_features.append(
        feature["numeric_features"]
    )


    labels.append(
        row["label"]
    )


    if (index + 1) % 5000 == 0:

        print(
            f"{index + 1}/{total} completed"
        )


print()

print(
    "Feature Extraction Completed."
)

print()


# ====================================================
# Train / Test Split
# ====================================================

print("=" * 60)
print("Splitting Dataset...")
print("=" * 60)


(
    X_train_text,
    X_test_text,

    X_train_original,
    X_test_original,

    X_train_num,
    X_test_num,

    y_train,
    y_test

) = train_test_split(

    texts,

    original_messages,

    numeric_features,

    labels,

    test_size=TEST_SIZE,

    random_state=RANDOM_STATE,

    stratify=labels
)


print()

print(
    "Training Samples :",
    len(X_train_text)
)

print(
    "Testing Samples  :",
    len(X_test_text)
)

print()


# ====================================================
# TF-IDF
# ====================================================

print("=" * 60)
print("Building TF-IDF Features...")
print("=" * 60)


fit_vectorizers(
    X_train_text
)


X_train_text = transform(
    X_train_text
)


X_test_text = transform(
    X_test_text
)


print()

print(
    "TF-IDF Completed"
)

print()


# ====================================================
# Numeric Features
# ====================================================

print("=" * 60)
print("Scaling Numeric Features...")
print("=" * 60)


scaler = StandardScaler()


X_train_num = scaler.fit_transform(
    np.array(X_train_num)
)


X_test_num = scaler.transform(
    np.array(X_test_num)
)


X_train_num = csr_matrix(
    X_train_num
)


X_test_num = csr_matrix(
    X_test_num
)


print()

print(
    "Scaling Completed"
)

print()


# ====================================================
# Merge Features
# ====================================================

print("=" * 60)
print("Combining Features...")
print("=" * 60)


X_train = hstack(
    [
        X_train_text,
        X_train_num
    ]
)


X_test = hstack(
    [
        X_test_text,
        X_test_num
    ]
)


print()

print(
    "Training Shape :",
    X_train.shape
)

print(
    "Testing Shape  :",
    X_test.shape
)

print()


# ====================================================
# Build Models
# ====================================================

print("=" * 60)
print("Preparing Models...")
print("=" * 60)


models = build_models()


print()

print(
    "Available Models:"
)

for name in models:

    print(
        " -",
        name
    )


print()


# ====================================================
# Train and Compare Models
# ====================================================

print("=" * 70)
print("TRAINING AND COMPARING MODELS")
print("=" * 70)


model_results = {}


for model_name, current_model in models.items():

    print()

    print("=" * 70)

    print(
        f"TRAINING MODEL: {model_name.upper()}"
    )

    print("=" * 70)


    current_model.fit(
        X_train,
        y_train
    )


    print()

    print(
        f"{model_name.upper()} TRAINING COMPLETED"
    )


    # ------------------------------------------------
    # Prediction
    # ------------------------------------------------

    y_pred = current_model.predict(
        X_test
    )


    # ------------------------------------------------
    # Metrics
    # ------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )


    precision = precision_score(
        y_test,
        y_pred,
        pos_label="spam",
        zero_division=0
    )


    recall = recall_score(
        y_test,
        y_pred,
        pos_label="spam",
        zero_division=0
    )


    f1 = f1_score(
        y_test,
        y_pred,
        pos_label="spam",
        zero_division=0
    )


    model_results[model_name] = {

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1": f1

    }


# ====================================================
# Model Comparison
# ====================================================

print()

print("=" * 90)
print("MODEL COMPARISON")
print("=" * 90)

print()

print(
    f"{'MODEL':<15}"
    f"{'ACCURACY':<15}"
    f"{'PRECISION':<15}"
    f"{'RECALL':<15}"
    f"{'F1 SCORE':<15}"
)

print(
    "-" * 90
)


for name, metrics in model_results.items():

    print(

        f"{name:<15}"

        f"{metrics['accuracy']:.4f}"
        f"{'':10}"

        f"{metrics['precision']:.4f}"
        f"{'':10}"

        f"{metrics['recall']:.4f}"
        f"{'':10}"

        f"{metrics['f1']:.4f}"

    )


# ====================================================
# Select Best Model
# ====================================================

best_model_name = max(

    model_results,

    key=lambda name:
    model_results[name]["f1"]

)


model = models[
    best_model_name
]


metrics = model_results[
    best_model_name
]


print()

print("=" * 70)

print(
    f"BEST MODEL: {best_model_name.upper()}"
)

print("=" * 70)

print()

print(
    "Accuracy  :",
    round(
        metrics["accuracy"] * 100,
        2
    ),
    "%"
)

print(
    "Precision :",
    round(
        metrics["precision"] * 100,
        2
    ),
    "%"
)

print(
    "Recall    :",
    round(
        metrics["recall"] * 100,
        2
    ),
    "%"
)

print(
    "F1 Score  :",
    round(
        metrics["f1"] * 100,
        2
    ),
    "%"
)

print()


# ====================================================
# False Negative Analysis
# ====================================================

print("=" * 70)
print("MISSED SCAM MESSAGES")
print("=" * 70)


predictions = model.predict(
    X_test
)


count = 0


for message, actual, predicted in zip(

    X_test_original,

    y_test,

    predictions

):

    if (
        actual == "spam"
        and predicted == "ham"
    ):

        print()

        print(
            "----------------------------------------"
        )

        print(
            message
        )

        count += 1


        if count == 30:

            break


print()

print(
    "Displayed first 30 missed scam messages."
)

print()


# ====================================================
# Save Analysis Report
# ====================================================

from sms.analysis import analyze_predictions


y_pred = model.predict(
    X_test
)


results = analyze_predictions(

    X_test_original,

    y_test,

    y_pred

)


ANALYSIS_PATH = os.path.join(

    MODEL_DIR,

    "model_analysis.csv"

)


results.to_csv(

    ANALYSIS_PATH,

    index=False

)


print()

print(
    "Analysis Report Saved:"
)

print(
    ANALYSIS_PATH
)

print()


# ====================================================
# Save Best Model
# ====================================================

print("=" * 60)
print("Saving Best Model...")
print("=" * 60)


joblib.dump(

    model,

    MODEL_PATH

)


joblib.dump(

    word_vectorizer,

    WORD_PATH

)


joblib.dump(

    char_vectorizer,

    CHAR_PATH

)


joblib.dump(

    scaler,

    SCALER_PATH

)


print()

print(
    "Best Model Saved Successfully."
)

print()

print(
    "Selected Model :",
    best_model_name
)

print(
    "Model          :",
    MODEL_PATH
)

print(
    "Word TFIDF     :",
    WORD_PATH
)

print(
    "Char TFIDF     :",
    CHAR_PATH
)

print(
    "Scaler         :",
    SCALER_PATH
)

print()


# ====================================================
# Final Result
# ====================================================

print("=" * 70)
print("TRAINING COMPLETED SUCCESSFULLY")
print("=" * 70)

print()

print(
    "Best Model :",
    best_model_name.upper()
)

print(
    "Accuracy   :",
    round(
        metrics["accuracy"] * 100,
        2
    ),
    "%"
)

print(
    "Precision  :",
    round(
        metrics["precision"] * 100,
        2
    ),
    "%"
)

print(
    "Recall     :",
    round(
        metrics["recall"] * 100,
        2
    ),
    "%"
)

print(
    "F1 Score   :",
    round(
        metrics["f1"] * 100,
        2
    ),
    "%"
)

print()

print(
    "Model Analysis:"
)

print(
    ANALYSIS_PATH
)

print()