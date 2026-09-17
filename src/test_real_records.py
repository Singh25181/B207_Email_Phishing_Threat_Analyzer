import os
import sys

import joblib
import numpy as np
import pandas as pd


# PATHS

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATA_PATH = os.path.join(
    BASE_DIR,
    "data",
    "email_phishing_data.csv"
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "phishing_model.pkl"
)


FEATURE_COLUMNS = [
    "num_words",
    "num_unique_words",
    "num_stopwords",
    "num_links",
    "num_unique_domains",
    "num_email_addresses",
    "num_spelling_errors",
    "num_urgent_keywords"
]


# LOAD DATA

df = pd.read_csv(
    DATA_PATH
)

df = df.drop_duplicates()

print("\n" + "=" * 70)
print("REAL DATASET PREDICTION TEST")
print("=" * 70)

print(
    f"Clean dataset records: {len(df):,}"
)

# LOAD MODEL

package = joblib.load(
    MODEL_PATH
)

model = package["model"]


# SELECT REAL RECORDS

safe_record = (
    df[df["label"] == 0]
    .sample(
        n=1,
        random_state=42
    )
)

phishing_record = (
    df[df["label"] == 1]
    .sample(
        n=1,
        random_state=42
    )
)


# TEST FUNCTION

def test_record(record, expected_label):

    X = record[
        FEATURE_COLUMNS
    ].copy()

    X_transformed = np.log1p(
        X
    )

    prediction = model.predict(
        X_transformed
    )[0]

    probability = model.predict_proba(
        X_transformed
    )[0]

    phishing_probability = probability[1]

    safe_probability = probability[0]

    print(
        "\n" + "-" * 70
    )

    if expected_label == 0:
        expected_text = "SAFE"
    else:
        expected_text = "PHISHING"

    if prediction == 0:
        prediction_text = "SAFE"
    else:
        prediction_text = "PHISHING"

    print(
        f"Actual dataset label : {expected_text}"
    )

    print(
        f"Model prediction      : {prediction_text}"
    )

    print(
        f"Phishing probability  : "
        f"{phishing_probability * 100:.2f}%"
    )

    print(
        f"Safe probability      : "
        f"{safe_probability * 100:.2f}%"
    )

    print(
        "\nFeature values:"
    )

    print(
        X.to_string(
            index=False
        )
    )


# TEST SAFE RECORD

print(
    "\nTEST 1: REAL SAFE RECORD"
)

test_record(
    safe_record,
    0
)


# TEST PHISHING RECORD

print(
    "\nTEST 2: REAL PHISHING RECORD"
)

test_record(
    phishing_record,
    1
)


print(
    "\n" + "=" * 70
)

print(
    "REAL DATASET TEST COMPLETED"
)

print(
    "=" * 70
)