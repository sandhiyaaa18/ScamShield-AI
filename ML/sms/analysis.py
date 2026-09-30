import pandas as pd

def analyze_predictions(
    messages,
    y_true,
    y_pred
):

    results = pd.DataFrame({

        "message": messages,

        "actual": y_true,

        "predicted": y_pred

    })

    results["status"] = "Correct"

    results.loc[
        results.actual != results.predicted,
        "status"
    ] = "Wrong"

    return results