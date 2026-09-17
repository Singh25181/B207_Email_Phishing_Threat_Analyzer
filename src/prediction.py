import os
import sys

import joblib
import numpy as np
import pandas as pd


# PROJECT PATH

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "phishing_model.pkl"
)


# FEATURE COLUMNS

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

# RISK LEVEL

def determine_risk_level(phishing_probability):
    """
    Determine the risk level based on phishing probability.

    HIGH   : >= 70%
    MEDIUM : >= 40% and < 70%
    LOW    : < 40%
    """

    if phishing_probability >= 0.70:
        return "HIGH"

    elif phishing_probability >= 0.40:
        return "MEDIUM"

    else:
        return "LOW"

# BACKWARD COMPATIBILITY

def determine_risk(phishing_probability):
    """
    Compatibility function used by the test suite.
    """

    return determine_risk_level(
        phishing_probability
    )


# LOAD MODEL

def load_model():
    """
    Load the trained phishing detection model.
    """

    if not os.path.exists(MODEL_PATH):

        print("\nError: Trained model was not found.")

        print(
            f"Expected location:\n{MODEL_PATH}"
        )

        sys.exit(1)

    try:

        package = joblib.load(
            MODEL_PATH
        )

    except Exception as error:

        print(
            f"\nError loading trained model: {error}"
        )

        sys.exit(1)

    return package


# GET EMAIL FEATURES

def get_email_features():
    """
    Collect the eight engineered email security
    indicators from the user.

    Returns:
        pandas DataFrame
        or None if invalid input is provided.
    """

    print(
        "\n" + "=" * 60
    )

    print(
        "ENTER EMAIL FEATURES"
    )

    print(
        "=" * 60
    )

    try:

        num_words = int(
            input("Number of words: ")
        )

        num_unique_words = int(
            input("Number of unique words: ")
        )

        num_stopwords = int(
            input("Number of stopwords: ")
        )

        num_links = int(
            input("Number of links: ")
        )

        num_unique_domains = int(
            input("Number of unique domains: ")
        )

        num_email_addresses = int(
            input("Number of email addresses: ")
        )

        num_spelling_errors = int(
            input("Number of spelling errors: ")
        )

        num_urgent_keywords = int(
            input("Number of urgent keywords: ")
        )

    except ValueError:

        print(
            "\nPlease enter valid numerical values."
        )

        return None

    values = [
        num_words,
        num_unique_words,
        num_stopwords,
        num_links,
        num_unique_domains,
        num_email_addresses,
        num_spelling_errors,
        num_urgent_keywords
    ]

    # Validate values

    if any(
        value < 0
        for value in values
    ):

        print(
            "\nFeature values cannot be negative."
        )

        return None

    # Create DataFrame

    features = pd.DataFrame(
        [values],
        columns=FEATURE_COLUMNS
    )

    return features



# COMPATIBILITY FUNCTION

def get_feature_input():
    """
    Compatibility wrapper for existing application code.
    """

    return get_email_features()


# PREDICT EMAIL

def predict_email(
    features,
    package=None
):
   

    # Load model if not supplied
 
    if package is None:

        package = load_model()

    model = package["model"]



    # Ensure correct feature order

    missing_columns = [
        column
        for column in FEATURE_COLUMNS
        if column not in features.columns
    ]

    if missing_columns:

        raise ValueError(
            "Missing feature columns: "
            + ", ".join(missing_columns)
        )


    features = features[
        FEATURE_COLUMNS
    ]


  
    # Apply log1p transformation
    # Same transformation used during training

    transformed_features = np.log1p(
        features
    )


    # Prediction

    prediction = model.predict(
        transformed_features
    )[0]


    # Probability
  
    probabilities = model.predict_proba(
        transformed_features
    )[0]


    safe_probability = float(
        probabilities[0]
    )

    phishing_probability = float(
        probabilities[1]
    )


    # Risk

    risk_level = determine_risk_level(
        phishing_probability
    )


    return (
        int(prediction),
        phishing_probability,
        safe_probability,
        risk_level
    )

# DISPLAY PREDICTION

def display_prediction(
    prediction,
    phishing_probability=None,
    safe_probability=None,
    risk_level=None
):
    """
    Display prediction results.

    This function accepts both the complete prediction
    result and the older single-result calling style.
    """

    # Support dictionary-style result if supplied

    if isinstance(
        prediction,
        dict
    ):

        result = prediction

        prediction = result.get(
            "prediction"
        )

        phishing_probability = result.get(
            "phishing_probability"
        )

        safe_probability = result.get(
            "safe_probability"
        )

        risk_level = result.get(
            "risk_level"
        )


    # Convert prediction to text

    if prediction == 1:

        prediction_text = "PHISHING"

    else:

        prediction_text = "SAFE"


    # Display

    print(
        "\n" + "=" * 60
    )

    print(
        "EMAIL ANALYSIS RESULT"
    )

    print(
        "=" * 60
    )

    print(
        f"Prediction          : {prediction_text}"
    )

    if phishing_probability is not None:

        print(
            f"Phishing Probability: "
            f"{phishing_probability * 100:.2f}%"
        )

    if safe_probability is not None:

        print(
            f"Safe Probability    : "
            f"{safe_probability * 100:.2f}%"
        )

    if risk_level is not None:

        print(
            f"Risk Level          : {risk_level}"
        )

    print(
        "=" * 60
    )


# DISPLAY RESULT

def display_result(
    prediction,
    phishing_probability,
    safe_probability,
    risk_level
):
    """
    Compatibility wrapper.
    """

    return display_prediction(
        prediction,
        phishing_probability,
        safe_probability,
        risk_level
    )


# MAIN

def main():

    package = load_model()

    features = get_email_features()

    if features is None:

        return

    (
        prediction,
        phishing_probability,
        safe_probability,
        risk_level
    ) = predict_email(
        features,
        package
    )

    display_prediction(
        prediction,
        phishing_probability,
        safe_probability,
        risk_level
    )


# ENTRY POINT

if __name__ == "__main__":

    main()