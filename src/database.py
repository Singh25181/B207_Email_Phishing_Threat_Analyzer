import os
import sqlite3
from datetime import datetime

import pandas as pd


# PROJECT PATH

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATABASE_DIR = os.path.join(
    BASE_DIR,
    "database"
)

DATABASE_PATH = os.path.join(
    DATABASE_DIR,
    "phishing_analysis.db"
)


# DATABASE INITIALISATION

def initialize_database():
    """
    Create the SQLite database and email_analysis table
    if they do not already exist.
    """

    os.makedirs(
        DATABASE_DIR,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS email_analysis (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp DATETIME NOT NULL,

            num_words INTEGER NOT NULL,

            num_unique_words INTEGER NOT NULL,

            num_stopwords INTEGER NOT NULL,

            num_links INTEGER NOT NULL,

            num_unique_domains INTEGER NOT NULL,

            num_email_addresses INTEGER NOT NULL,

            num_spelling_errors INTEGER NOT NULL,

            num_urgent_keywords INTEGER NOT NULL,

            prediction INTEGER NOT NULL,

            phishing_probability REAL NOT NULL,

            safe_probability REAL NOT NULL,

            risk_level TEXT NOT NULL

        )
        """
    )

    connection.commit()

    connection.close()

    return True


# SAVE ANALYSIS

def save_analysis(
    features,
    prediction,
    phishing_probability,
    safe_probability,
    risk_level
):
    """
    Save an email analysis result into the SQLite database.

    A timestamp is explicitly generated and inserted so that
    the function works with the existing database schema.
    """

    initialize_database()

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()


    # Generate timestamp

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    # Extract feature values

    values = [

        timestamp,

        int(
            features["num_words"].iloc[0]
        ),

        int(
            features["num_unique_words"].iloc[0]
        ),

        int(
            features["num_stopwords"].iloc[0]
        ),

        int(
            features["num_links"].iloc[0]
        ),

        int(
            features["num_unique_domains"].iloc[0]
        ),

        int(
            features["num_email_addresses"].iloc[0]
        ),

        int(
            features["num_spelling_errors"].iloc[0]
        ),

        int(
            features["num_urgent_keywords"].iloc[0]
        ),

        int(
            prediction
        ),

        float(
            phishing_probability
        ),

        float(
            safe_probability
        ),

        str(
            risk_level
        )
    ]

    # Insert analysis

    cursor.execute(
        """
        INSERT INTO email_analysis (

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

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        values
    )


    connection.commit()

    analysis_id = cursor.lastrowid

    connection.close()


    return analysis_id


# GET ANALYSIS HISTORY

def get_analysis_history():
    """
    Retrieve all stored email analysis records.

    Returns:
        pandas DataFrame
    """

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


# GET DETECTION STATISTICS

def get_statistics():
    """
    Calculate statistics from stored analyses.

    Both the original test-suite keys and the newer
    application keys are returned.
    """

    initialize_database()

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    # Total analyses

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM email_analysis
        """
    )

    total = cursor.fetchone()[0]


    # Phishing detections

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM email_analysis
        WHERE prediction = 1
        """
    )

    phishing = cursor.fetchone()[0]

    # Safe detections

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM email_analysis
        WHERE prediction = 0
        """
    )

    safe = cursor.fetchone()[0]


    # HIGH risk

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM email_analysis
        WHERE risk_level = 'HIGH'
        """
    )

    high_risk = cursor.fetchone()[0]


    # MEDIUM risk

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM email_analysis
        WHERE risk_level = 'MEDIUM'
        """
    )

    medium_risk = cursor.fetchone()[0]


    # LOW risk

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM email_analysis
        WHERE risk_level = 'LOW'
        """
    )

    low_risk = cursor.fetchone()[0]


    connection.close()


    # Return statistics

    return {

        # Existing test-suite keys
        "total": total,

        "phishing": phishing,

        "safe": safe,

        # Main application keys
        "total_analyses": total,

        "phishing_detected": phishing,

        "safe_detected": safe,

        # Risk statistics
        "high_risk": high_risk,

        "medium_risk": medium_risk,

        "low_risk": low_risk
    }


# EXPORT ANALYSIS HISTORY

def export_analysis_history(
    output_path=None
):
    """
    Export all analysis records to a CSV file.
    """

    if output_path is None:

        results_dir = os.path.join(
            BASE_DIR,
            "results"
        )

        os.makedirs(
            results_dir,
            exist_ok=True
        )

        output_path = os.path.join(
            results_dir,
            "analysis_history.csv"
        )


    dataframe = get_analysis_history()


    dataframe.to_csv(
        output_path,
        index=False
    )


    return output_path


# MAIN

if __name__ == "__main__":

    initialize_database()

    print(
        "Database initialised successfully."
    )

    print(
        f"Database location:\n{DATABASE_PATH}"
    )