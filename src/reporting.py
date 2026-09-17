import os
import sqlite3
import pandas as pd

from database import (
    DATABASE_PATH,
    initialize_database,
    get_statistics
)


CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

BASE_DIR = os.path.dirname(
    CURRENT_DIR
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "results"
)

REPORT_PATH = os.path.join(
    RESULTS_DIR,
    "analysis_history.csv"
)


def create_results_directory():

    os.makedirs(
        RESULTS_DIR,
        exist_ok=True
    )


def display_statistics():

    initialize_database()

    statistics = get_statistics()

    print("\n" + "=" * 60)
    print("PHISHING DETECTION STATISTICS")
    print("=" * 60)

    print(
        f"Total analyses : "
        f"{statistics['total']}"
    )

    print(
        f"Phishing       : "
        f"{statistics['phishing']}"
    )

    print(
        f"Safe           : "
        f"{statistics['safe']}"
    )

    print("-" * 60)

    print(
        f"High risk      : "
        f"{statistics['high_risk']}"
    )

    print(
        f"Medium risk    : "
        f"{statistics['medium_risk']}"
    )

    print(
        f"Low risk       : "
        f"{statistics['low_risk']}"
    )

    print("=" * 60)


def get_analysis_history():

    initialize_database()

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    query = """
        SELECT
            id,
            timestamp,
            num_words,
            num_unique_words,
            num_stopwords,
            num_links,
            num_unique_domains,
            num_email_addresses,
            num_spelling_errors,
            num_urgent_keywords,
            prediction,
            phishing_probability,
            safe_probability,
            risk_level

        FROM email_analysis

        ORDER BY id DESC
    """

    dataframe = pd.read_sql_query(
        query,
        connection
    )

    connection.close()

    return dataframe


def display_analysis_history():

    dataframe = get_analysis_history()

    print("\n" + "=" * 100)
    print("ANALYSIS HISTORY")
    print("=" * 100)

    if dataframe.empty:

        print(
            "No email analyses have been stored yet."
        )

        return

    display_columns = [
        "id",
        "timestamp",
        "prediction",
        "phishing_probability",
        "risk_level"
    ]

    display_df = dataframe[
        display_columns
    ].copy()

    display_df[
        "phishing_probability"
    ] = (
        display_df[
            "phishing_probability"
        ] * 100
    ).round(2)

    print(
        display_df.to_string(
            index=False
        )
    )


def export_report():

    create_results_directory()

    dataframe = get_analysis_history()

    dataframe.to_csv(
        REPORT_PATH,
        index=False
    )

    print(
        f"\nAnalysis report exported to:\n"
        f"{REPORT_PATH}"
    )

    return REPORT_PATH


def generate_summary_report():

    create_results_directory()

    statistics = get_statistics()

    report_path = os.path.join(
        RESULTS_DIR,
        "summary_report.txt"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "B207 EMAIL PHISHING THREAT ANALYZER\n"
        )

        file.write(
            "=" * 50 + "\n\n"
        )

        file.write(
            f"Total analyses: "
            f"{statistics['total']}\n"
        )

        file.write(
            f"Phishing detections: "
            f"{statistics['phishing']}\n"
        )

        file.write(
            f"Safe detections: "
            f"{statistics['safe']}\n"
        )

        file.write(
            f"High-risk detections: "
            f"{statistics['high_risk']}\n"
        )

        file.write(
            f"Medium-risk detections: "
            f"{statistics['medium_risk']}\n"
        )

        file.write(
            f"Low-risk detections: "
            f"{statistics['low_risk']}\n"
        )

    print(
        f"\nSummary report created:\n"
        f"{report_path}"
    )

    return report_path


if __name__ == "__main__":

    display_statistics()

    display_analysis_history()

    export_report()

    generate_summary_report()