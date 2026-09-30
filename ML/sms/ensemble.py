"""
====================================================
ScamShield AI
Models
====================================================
"""

from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression

from sms.config import *


def build_models():

    svm = LinearSVC(

        C=2.0,

        class_weight="balanced",

        random_state=RANDOM_STATE,

        dual="auto"

    )

    lr = LogisticRegression(

        C=2.0,

        max_iter=5000,

        class_weight="balanced",

        random_state=RANDOM_STATE,

        solver="liblinear"

    )

    return {

        "svm": svm,

        "lr": lr

    }


if __name__ == "__main__":

    models = build_models()

    print("=" * 60)

    print("AVAILABLE MODELS")

    print("=" * 60)

    print()

    for name in models:

        print(name)