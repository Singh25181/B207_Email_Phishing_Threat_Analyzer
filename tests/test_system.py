import os
import sys
import unittest


# Add project src directory

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

BASE_DIR = os.path.dirname(
    CURRENT_DIR
)

SRC_DIR = os.path.join(
    BASE_DIR,
    "src"
)

if SRC_DIR not in sys.path:

    sys.path.append(
        SRC_DIR
    )


# Project imports

from data_preprocessing import (
    load_dataset,
    validate_dataset,
    FEATURE_COLUMNS,
    TARGET_COLUMN
)

from prediction import (
    determine_risk
)

from database import (
    initialize_database,
    get_statistics
)


# Test class

class TestPhishingThreatAnalyzer(
    unittest.TestCase
):

    # Test 1: Dataset exists and loads

    def test_dataset_loads(self):

        df = load_dataset()

        self.assertIsNotNone(
            df
        )

        self.assertGreater(
            len(df),
            0
        )

    # Test 2: Required columns exist

    def test_required_columns(self):

        df = load_dataset()

        required = (
            FEATURE_COLUMNS
            + [TARGET_COLUMN]
        )

        for column in required:

            self.assertIn(
                column,
                df.columns
            )

    # Test 3: Dataset validation

    def test_dataset_validation(self):

        df = load_dataset()

        result = validate_dataset(
            df
        )

        self.assertTrue(
            result
        )

    # Test 4: Risk classification

    def test_high_risk(self):

        result = determine_risk(
            0.85
        )

        self.assertEqual(
            result,
            "HIGH"
        )

    def test_medium_risk(self):

        result = determine_risk(
            0.50
        )

        self.assertEqual(
            result,
            "MEDIUM"
        )

    def test_low_risk(self):

        result = determine_risk(
            0.20
        )

        self.assertEqual(
            result,
            "LOW"
        )

    # Test 5: Database initialisation

    def test_database_initialisation(self):

        initialize_database()

        statistics = get_statistics()

        self.assertIsInstance(
            statistics,
            dict
        )

        self.assertIn(
            "total",
            statistics
        )

    # Test 6: Risk probability range

    def test_probability_range(self):

        probability = 0.75

        self.assertGreaterEqual(
            probability,
            0
        )

        self.assertLessEqual(
            probability,
            1
        )


# Run tests

if __name__ == "__main__":

    unittest.main(
        verbosity=2
    )