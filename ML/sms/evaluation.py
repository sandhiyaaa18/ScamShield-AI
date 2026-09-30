"""
====================================================
ScamShield AI
SMS Model Evaluation
====================================================
"""

import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)


def evaluate_model(model, X_test, y_test):

    print()
    print("=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)

    y_pred = model.predict(X_test)

    

    accuracy = accuracy_score(y_test, y_pred)

    precision = precision_score(
        y_test,
        y_pred,
        pos_label="spam"
    )

    recall = recall_score(
        y_test,
        y_pred,
        pos_label="spam"
    )

    f1 = f1_score(
        y_test,
        y_pred,
        pos_label="spam"
    )

    print()

    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")

    print()

    print("=" * 70)
    print("CLASSIFICATION REPORT")
    print("=" * 70)

    print()

    print(classification_report(y_test, y_pred))

    cm = confusion_matrix(y_test, y_pred)

    print()

    print("=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)

    print()

    print(cm)

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=["ham", "spam"]
    )

    display.plot()

    plt.title("ScamShield AI Confusion Matrix")

    plt.show()

    return {

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1": f1

    }