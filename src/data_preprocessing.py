import os

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split


# PROJECT PATHS

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

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "results"
)

FIGURES_DIR = os.path.join(
    RESULTS_DIR,
    "figures"
)


os.makedirs(
    RESULTS_DIR,
    exist_ok=True
)

os.makedirs(
    FIGURES_DIR,
    exist_ok=True
)


# SETTINGS

RANDOM_STATE = 42
TEST_SIZE = 0.20


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

TARGET_COLUMN = "label"

# LOAD DATASET

def load_dataset():

    if not os.path.exists(DATA_PATH):

        raise FileNotFoundError(
            f"Dataset not found:\n{DATA_PATH}"
        )

    df = pd.read_csv(
        DATA_PATH
    )

    print(
        "\nDataset loaded successfully."
    )

    print(
        f"Rows: {len(df):,}"
    )

    print(
        f"Columns: {len(df.columns)}"
    )

    return df


# DATASET VALIDATION

def validate_dataset(df):
    """Validate the dataset structure and values."""

    required_columns = [
        "num_words",
        "num_unique_words",
        "num_stopwords",
        "num_links",
        "num_unique_domains",
        "num_email_addresses",
        "num_spelling_errors",
        "num_urgent_keywords",
        "label"
    ]

    for column in required_columns:
        if column not in df.columns:
            raise ValueError(f"Missing required column: {column}")

    feature_columns = required_columns[:-1]

    if df[feature_columns].isnull().any().any():
        raise ValueError("Missing values found in feature columns.")

    if (df[feature_columns] < 0).any().any():
        raise ValueError("Negative values found in feature columns.")

    if not df["label"].isin([0, 1]).all():
        raise ValueError("Label column must contain only 0 and 1.")

    print("\nDataset validation completed successfully.")
    return True


# DATA QUALITY REPORT

def generate_data_quality_report(df):

    quality_report = pd.DataFrame({

        "column":
            df.columns,

        "data_type":
            [
                str(dtype)
                for dtype in df.dtypes
            ],

        "missing_values":
            [
                int(df[column].isna().sum())
                for column in df.columns
            ],

        "unique_values":
            [
                int(df[column].nunique())
                for column in df.columns
            ]

    })

    print(
        "\nData Quality Report"
    )

    print(
        "-" * 60
    )

    print(
        quality_report.to_string(
            index=False
        )
    )

    output_path = os.path.join(
        RESULTS_DIR,
        "data_quality_report.csv"
    )

    quality_report.to_csv(
        output_path,
        index=False
    )

    print(
        f"\nSaved to: {output_path}"
    )

    return quality_report


# DATA CLEANING

def clean_dataset(df):

    print(
        "\nData cleaning"
    )

    print(
        "-" * 60
    )

    original_rows = len(df)

    # Remove missing values
    df_clean = df.dropna().copy()

    missing_removed = (
        original_rows
        - len(df_clean)
    )

    print(
        "Rows removed because of "
        f"missing values: {missing_removed}"
    )

    # Remove negative feature values
    negative_mask = (
        df_clean[FEATURE_COLUMNS] < 0
    ).any(
        axis=1
    )

    negative_removed = int(
        negative_mask.sum()
    )

    df_clean = df_clean[
        ~negative_mask
    ].copy()

    print(
        "Rows removed because of "
        f"negative values: {negative_removed}"
    )

    # Duplicate analysis

    print(
        "\nDuplicate analysis"
    )

    print(
        "-" * 60
    )

    duplicate_count = int(
        df_clean.duplicated().sum()
    )

    print(
        f"Duplicate rows found: "
        f"{duplicate_count:,}"
    )

    print(
        f"Rows before removal: "
        f"{len(df_clean):,}"
    )

    df_clean = df_clean.drop_duplicates()

    print(
        f"Rows after removal:  "
        f"{len(df_clean):,}"
    )

    return df_clean


# CLASS DISTRIBUTION

def display_class_distribution(df):

    safe_count = int(
        (df[TARGET_COLUMN] == 0).sum()
    )

    phishing_count = int(
        (df[TARGET_COLUMN] == 1).sum()
    )

    total = len(df)

    safe_percentage = (
        safe_count / total * 100
    )

    phishing_percentage = (
        phishing_count / total * 100
    )

    print(
        "\nClass Distribution"
    )

    print(
        "-" * 60
    )

    print(
        f"Safe emails     : "
        f"{safe_count:,} "
        f"({safe_percentage:.2f}%)"
    )

    print(
        f"Phishing emails : "
        f"{phishing_count:,} "
        f"({phishing_percentage:.2f}%)"
    )


# EDA VISUALISATIONS

def create_eda_visualisations(df):

    # Class distribution

    class_counts = (
        df[TARGET_COLUMN]
        .value_counts()
        .sort_index()
    )

    figure, ax = plt.subplots(
        figsize=(8, 6)
    )

    ax.bar(
        ["Safe", "Phishing"],
        class_counts.values
    )

    ax.set_title(
        "Email Class Distribution"
    )

    ax.set_xlabel(
        "Email Class"
    )

    ax.set_ylabel(
        "Number of Emails"
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            FIGURES_DIR,
            "class_distribution.png"
        ),
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


    # Average feature distribution

    grouped_features = (
        df.groupby(
            TARGET_COLUMN
        )[FEATURE_COLUMNS]
        .mean()
        .T
    )

    figure, ax = plt.subplots(
        figsize=(12, 7)
    )

    x = np.arange(
        len(FEATURE_COLUMNS)
    )

    width = 0.35

    ax.bar(
        x - width / 2,
        grouped_features[0],
        width,
        label="Safe"
    )

    ax.bar(
        x + width / 2,
        grouped_features[1],
        width,
        label="Phishing"
    )

    ax.set_xlabel(
        "Email Security Feature"
    )

    ax.set_ylabel(
        "Average Value"
    )

    ax.set_title(
        "Average Feature Values by Email Class"
    )

    ax.set_xticks(
        x
    )

    ax.set_xticklabels(
        FEATURE_COLUMNS,
        rotation=45,
        ha="right"
    )

    ax.legend()

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            FIGURES_DIR,
            "feature_distribution.png"
        ),
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    # Correlation matrix

    correlation = (
        df[
            FEATURE_COLUMNS
            + [TARGET_COLUMN]
        ]
        .corr()
    )

    figure, ax = plt.subplots(
        figsize=(10, 8)
    )

    image = ax.imshow(
        correlation,
        aspect="auto"
    )

    ax.set_xticks(
        range(
            len(correlation.columns)
        )
    )

    ax.set_yticks(
        range(
            len(correlation.columns)
        )
    )

    ax.set_xticklabels(
        correlation.columns,
        rotation=45,
        ha="right"
    )

    ax.set_yticklabels(
        correlation.columns
    )

    ax.set_title(
        "Correlation Matrix of Email Features"
    )

    figure.colorbar(
        image,
        ax=ax
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            FIGURES_DIR,
            "correlation_matrix.png"
        ),
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        "\nEDA visualisations created successfully."
    )


# PREPARE DATA

def prepare_data():

    df = load_dataset()

    validate_dataset(
        df
    )

    generate_data_quality_report(
        df
    )

    df = clean_dataset(
        df
    )

    display_class_distribution(
        df
    )

    X = df[
        FEATURE_COLUMNS
    ].copy()

    y = df[
        TARGET_COLUMN
    ].copy()

    # Train/test split

    X_train, X_test, y_train, y_test = train_test_split(

        X,
        y,

        test_size=TEST_SIZE,

        stratify=y,

        random_state=RANDOM_STATE

    )

    print(
        "\nTrain/Test Split"
    )

    print(
        "-" * 60
    )

    print(
        f"Training records: "
        f"{len(X_train):,}"
    )

    print(
        f"Testing records : "
        f"{len(X_test):,}"
    )

    print(
        "\nTraining class distribution:"
    )

    print(
        y_train.value_counts().sort_index()
    )

    print(
        "\nTesting class distribution:"
    )

    print(
        y_test.value_counts().sort_index()
    )

    # Log transformation

    X_train = np.log1p(
        X_train
    )

    X_test = np.log1p(
        X_test
    )

    # EDA
    create_eda_visualisations(
        df
    )

    print(
        "\nPreprocessing completed successfully."
    )

    # Return unscaled log-transformed data.
    # Scaling will be handled inside the ML pipeline.
    return (
        X_train,
        X_test,
        y_train,
        y_test,
        FEATURE_COLUMNS
    )

# RUN DIRECTLY

if __name__ == "__main__":

    prepare_data()