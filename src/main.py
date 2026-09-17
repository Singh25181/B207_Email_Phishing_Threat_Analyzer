import os
import sys


# ADD SRC DIRECTORY TO PYTHON PATH

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

if CURRENT_DIR not in sys.path:

    sys.path.insert(
        0,
        CURRENT_DIR
    )

# IMPORT PREDICTION FUNCTIONS

from prediction import (
    load_model,
    get_feature_input,
    predict_email,
    display_prediction
)


# IMPORT DATABASE FUNCTIONS

from database import (
    initialize_database,
    save_analysis,
    get_analysis_history,
    get_statistics,
    export_analysis_history
)


# PROJECT PATH

BASE_DIR = os.path.dirname(
    CURRENT_DIR
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "results"
)


# DISPLAY HEADER

def display_header():

    print(
        "\n\n" + "=" * 60
    )

    print(
        "       B207 EMAIL PHISHING THREAT ANALYZER"
    )

    print(
        "          Machine Learning System"
    )

    print(
        "=" * 60
    )

    print(
        "Analyses engineered email security indicators"
    )

    print(
        "=" * 60
    )


# DISPLAY MENU

def display_menu():

    print(
        "\n1. Analyse Email Features"
    )

    print(
        "2. View Analysis History"
    )

    print(
        "3. View Detection Statistics"
    )

    print(
        "4. Export Analysis Report"
    )

    print(
        "5. Generate Summary Report"
    )

    print(
        "6. Exit"
    )

    print(
        "-" * 60
    )


# ANALYSE EMAIL

def analyse_email():

    try:

        # Get user features

        features = get_feature_input()

        if features is None:

            print(
                "\nAnalysis cancelled because invalid input was provided."
            )

            return


        # Load trained model

        package = load_model()


        # Make prediction

        (
            prediction,
            phishing_probability,
            safe_probability,
            risk_level
        ) = predict_email(
            features,
            package
        )


        # Display prediction

        display_prediction(
            prediction,
            phishing_probability,
            safe_probability,
            risk_level
        )


        # Save to database

        analysis_id = save_analysis(
            features,
            prediction,
            phishing_probability,
            safe_probability,
            risk_level
        )


        print(
            f"\nAnalysis saved successfully."
        )

        print(
            f"Analysis ID: {analysis_id}"
        )


    except Exception as error:

        print(
            f"\nAn unexpected error occurred: {error}"
        )


# VIEW HISTORY

def view_analysis_history():

    try:

        dataframe = get_analysis_history()


        print(
            "\n" + "=" * 100
        )

        print(
            "ANALYSIS HISTORY"
        )

        print(
            "=" * 100
        )


        if dataframe.empty:

            print(
                "\nNo analysis records found."
            )

            return


        # ----------------------------------------------------
        # Create display copy
        # ----------------------------------------------------

        display_data = dataframe.copy()


        # ----------------------------------------------------
        # Convert prediction to text safely
        # ----------------------------------------------------

        display_data["prediction"] = display_data[
            "prediction"
        ].apply(
            lambda value:
            "PHISHING"
            if int(value) == 1
            else "SAFE"
        )


        # ----------------------------------------------------
        # Convert probabilities to percentages
        # ----------------------------------------------------

        display_data[
            "phishing_probability"
        ] = (
            display_data[
                "phishing_probability"
            ].astype(float) * 100
        ).round(2)


        display_data[
            "safe_probability"
        ] = (
            display_data[
                "safe_probability"
            ].astype(float) * 100
        ).round(2)


        # ----------------------------------------------------
        # Display history
        # ----------------------------------------------------

        print(
            display_data.to_string(
                index=False
            )
        )


        print(
            "\nTotal stored analyses:",
            len(dataframe)
        )


    except Exception as error:

        print(
            f"\nUnable to display history: {error}"
        )


# VIEW STATISTICS

def view_detection_statistics():

    try:

        statistics = get_statistics()


        print(
            "\n" + "=" * 60
        )

        print(
            "DETECTION STATISTICS"
        )

        print(
            "=" * 60
        )


        print(
            f"Total Analyses      : "
            f"{statistics['total_analyses']}"
        )

        print(
            f"Phishing Detected   : "
            f"{statistics['phishing_detected']}"
        )

        print(
            f"Safe Detected       : "
            f"{statistics['safe_detected']}"
        )

        print(
            "\nRisk Distribution"
        )

        print(
            "-" * 60
        )

        print(
            f"HIGH Risk           : "
            f"{statistics['high_risk']}"
        )

        print(
            f"MEDIUM Risk         : "
            f"{statistics['medium_risk']}"
        )

        print(
            f"LOW Risk            : "
            f"{statistics['low_risk']}"
        )


        print(
            "=" * 60
        )


    except Exception as error:

        print(
            f"\nUnable to generate statistics: {error}"
        )


# EXPORT REPORT

def export_report():

    try:

        os.makedirs(
            RESULTS_DIR,
            exist_ok=True
        )


        output_path = export_analysis_history()


        print(
            "\n" + "=" * 60
        )

        print(
            "ANALYSIS REPORT EXPORTED"
        )

        print(
            "=" * 60
        )

        print(
            f"File created:\n{output_path}"
        )


    except Exception as error:

        print(
            f"\nUnable to export report: {error}"
        )


# GENERATE SUMMARY REPORT


def generate_summary_report():

    try:

        os.makedirs(
            RESULTS_DIR,
            exist_ok=True
        )


        statistics = get_statistics()


        report_path = os.path.join(
            RESULTS_DIR,
            "summary_report.txt"
        )


        with open(
            report_path,
            "w",
            encoding="utf-8"
        ) as report:

            report.write(
                "B207 EMAIL PHISHING THREAT ANALYZER\n"
            )

            report.write(
                "=" * 60 + "\n\n"
            )

            report.write(
                "Detection Summary\n"
            )

            report.write(
                "-" * 60 + "\n"
            )

            report.write(
                f"Total Analyses: "
                f"{statistics['total_analyses']}\n"
            )

            report.write(
                f"Phishing Detected: "
                f"{statistics['phishing_detected']}\n"
            )

            report.write(
                f"Safe Detected: "
                f"{statistics['safe_detected']}\n"
            )

            report.write(
                f"High Risk: "
                f"{statistics['high_risk']}\n"
            )

            report.write(
                f"Medium Risk: "
                f"{statistics['medium_risk']}\n"
            )

            report.write(
                f"Low Risk: "
                f"{statistics['low_risk']}\n"
            )

            report.write(
                "\nRisk thresholds:\n"
            )

            report.write(
                "HIGH: phishing probability >= 70%\n"
            )

            report.write(
                "MEDIUM: phishing probability >= 40% and < 70%\n"
            )

            report.write(
                "LOW: phishing probability < 40%\n"
            )


        print(
            "\n" + "=" * 60
        )

        print(
            "SUMMARY REPORT GENERATED"
        )

        print(
            "=" * 60
        )

        print(
            f"File created:\n{report_path}"
        )


    except Exception as error:

        print(
            f"\nUnable to generate summary report: {error}"
        )

# MAIN APPLICATION LOOP

def main():

    # Initialise database

    initialize_database()


    # Check trained model

    try:

        load_model()

    except SystemExit:

        print(
            "\nPlease train the model before running the application."
        )

        return


    # Application loop

    while True:

        display_header()

        display_menu()


        try:

            choice = input(
                "Enter your choice: "
            ).strip()


        except KeyboardInterrupt:

            print(
                "\n\nApplication closed."
            )

            break


        # Option 1

        if choice == "1":

            analyse_email()


        # Option 2

        elif choice == "2":

            view_analysis_history()


        # Option 3

        elif choice == "3":

            view_detection_statistics()


        # Option 4

        elif choice == "4":

            export_report()


        # Option 5

        elif choice == "5":

            generate_summary_report()


        # Option 6

        elif choice == "6":

            print(
                "\nThank you for using "
                "B207 Email Phishing Threat Analyzer."
            )

            print(
                "Application closed."
            )

            break


        # Invalid option


        else:

            print(
                "\nInvalid choice."
            )

            print(
                "Please select an option from 1 to 6."
            )


# ENTRY POINT

if __name__ == "__main__":

    main()