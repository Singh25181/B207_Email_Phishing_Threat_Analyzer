import os
import sys
import warnings

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score
)

from sklearn.model_selection import (
    StratifiedKFold,
    cross_val_score
)

from sklearn.pipeline import Pipeline

from sklearn.preprocessing import StandardScaler


warnings.filterwarnings(
    "ignore"
)


# PATHS

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "results"
)

FIGURES_DIR = os.path.join(
    RESULTS_DIR,
    "figures"
)

MODELS_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODELS_DIR,
    "phishing_model.pkl"
)

RESULTS_PATH = os.path.join(
    RESULTS_DIR,
    "model_results.csv"
)


os.makedirs(
    RESULTS_DIR,
    exist_ok=True
)

os.makedirs(
    FIGURES_DIR,
    exist_ok=True
)

os.makedirs(
    MODELS_DIR,
    exist_ok=True
)


# IMPORT PREPROCESSING

try:

    from data_preprocessing import prepare_data

except ImportError:

    from src.data_preprocessing import prepare_data


# SETTINGS

RANDOM_STATE = 42
CV_FOLDS = 5

# HEADER

print(
    "\n" + "=" * 70
)

print(
    "B207 EMAIL PHISHING THREAT ANALYZER"
)

print(
    "MACHINE LEARNING TRAINING"
)

print(
    "=" * 70
)


# PREPARE DATA

try:

    (
        X_train,
        X_test,
        y_train,
        y_test,
        feature_columns
    ) = prepare_data()

except Exception as error:

    print(
        "\nError while preparing dataset:"
    )

    print(
        error
    )

    sys.exit(1)


print(
    "\nData preparation completed successfully."
)

# MODEL DEFINITIONS

logistic_regression = Pipeline(
    steps=[

        (
            "scaler",
            StandardScaler()
        ),

        (
            "classifier",
            LogisticRegression(
                class_weight="balanced",
                max_iter=1000,
                random_state=RANDOM_STATE
            )
        )

    ]
)


random_forest = Pipeline(
    steps=[

        (
            "scaler",
            StandardScaler()
        ),

        (
            "classifier",
            RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=RANDOM_STATE,
                n_jobs=-1
            )
        )

    ]
)


models = {

    "Logistic Regression":
        logistic_regression,

    "Random Forest":
        random_forest

}


# CROSS VALIDATION

cv = StratifiedKFold(

    n_splits=CV_FOLDS,

    shuffle=True,

    random_state=RANDOM_STATE

)


# RESULTS

results = []

# TRAIN MODELS

for model_name, model in models.items():

    print(
        "\n" + "=" * 70
    )

    print(
        f"Running {CV_FOLDS}-fold "
        f"cross-validation for "
        f"{model_name}..."
    )

    print(
        "=" * 70
    )


    # CROSS VALIDATION

    cv_scores = cross_val_score(

        model,

        X_train,

        y_train,

        cv=cv,

        scoring="f1",

        n_jobs=-1

    )


    print(
        "CV F1 scores:",
        np.round(
            cv_scores,
            4
        )
    )

    print(
        f"Mean CV F1: "
        f"{cv_scores.mean():.4f}"
    )

    print(
        f"Std CV F1: "
        f"{cv_scores.std():.4f}"
    )


    # FIT MODEL

    model.fit(

        X_train,

        y_train

    )


    # PREDICTIONS

    y_pred = model.predict(
        X_test
    )

    y_probability = model.predict_proba(
        X_test
    )[:, 1]


    # METRICS

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        y_probability
    )

    pr_auc = average_precision_score(
        y_test,
        y_probability
    )


    # DISPLAY

    print(
        "\n" + "=" * 70
    )

    print(
        model_name
    )

    print(
        "=" * 70
    )

    print(
        f"Accuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1-score : {f1:.4f}"
    )

    print(
        f"ROC-AUC  : {roc_auc:.4f}"
    )

    print(
        f"PR-AUC   : {pr_auc:.4f}"
    )


    # CONFUSION MATRIX

    cm = confusion_matrix(

        y_test,

        y_pred

    )

    print(
        "\nConfusion Matrix:"
    )

    print(
        cm
    )


    # CLASSIFICATION REPORT

    print(
        "\nClassification Report:"
    )

    print(

        classification_report(

            y_test,

            y_pred,

            target_names=[
                "Safe",
                "Phishing"
            ],

            zero_division=0

        )

    )


    # SAVE CONFUSION MATRIX

    figure, ax = plt.subplots(
        figsize=(7, 6)
    )

    display = ConfusionMatrixDisplay(

        confusion_matrix=cm,

        display_labels=[
            "Safe",
            "Phishing"
        ]

    )

    display.plot(

        ax=ax,

        values_format="d"

    )

    ax.set_title(
        f"Confusion Matrix - {model_name}"
    )

    plt.tight_layout()


    safe_name = (
        model_name
        .lower()
        .replace(
            " ",
            "_"
        )
    )


    confusion_path = os.path.join(

        FIGURES_DIR,

        f"confusion_matrix_{safe_name}.png"

    )


    plt.savefig(

        confusion_path,

        dpi=300,

        bbox_inches="tight"

    )

    plt.close()


    # STORE RESULTS

    results.append(

        {

            "Model":
                model_name,

            "Accuracy":
                accuracy,

            "Precision":
                precision,

            "Recall":
                recall,

            "F1_Score":
                f1,

            "ROC_AUC":
                roc_auc,

            "PR_AUC":
                pr_auc,

            "Mean_CV_F1":
                cv_scores.mean(),

            "Std_CV_F1":
                cv_scores.std()

        }

    )


# MODEL COMPARISON

results_df = pd.DataFrame(
    results
)


print(
    "\n" + "=" * 70
)

print(
    "MODEL COMPARISON"
)

print(
    "=" * 70
)

print(

    results_df.to_string(
        index=False
    )

)


# SAVE RESULTS

results_df.to_csv(

    RESULTS_PATH,

    index=False

)


print(
    f"\nModel results saved to:\n"
    f"{RESULTS_PATH}"
)


# MODEL COMPARISON CHART

figure, ax = plt.subplots(
    figsize=(10, 6)
)


x = np.arange(
    len(results_df)
)

width = 0.18


ax.bar(
    x - 1.5 * width,
    results_df["Accuracy"],
    width,
    label="Accuracy"
)

ax.bar(
    x - 0.5 * width,
    results_df["Precision"],
    width,
    label="Precision"
)

ax.bar(
    x + 0.5 * width,
    results_df["Recall"],
    width,
    label="Recall"
)

ax.bar(
    x + 1.5 * width,
    results_df["F1_Score"],
    width,
    label="F1-score"
)


ax.set_xlabel(
    "Machine Learning Model"
)

ax.set_ylabel(
    "Score"
)

ax.set_title(
    "Machine Learning Model Performance Comparison"
)

ax.set_xticks(
    x
)

ax.set_xticklabels(
    results_df["Model"]
)

ax.set_ylim(
    0,
    1
)

ax.legend()


plt.tight_layout()


comparison_path = os.path.join(

    FIGURES_DIR,

    "model_comparison.png"

)


plt.savefig(

    comparison_path,

    dpi=300,

    bbox_inches="tight"

)


plt.close()


print(
    f"Model comparison figure saved to:\n"
    f"{comparison_path}"
)


# SELECT FINAL MODEL

best_index = results_df[
    "F1_Score"
].idxmax()


best_model_name = results_df.loc[
    best_index,
    "Model"
]


best_model = models[
    best_model_name
]


# FIT FINAL MODEL

best_model.fit(

    X_train,

    y_train

)


# SAVE MODEL

model_package = {

    "model":
        best_model,

    "features":
        feature_columns,

    "model_name":
        best_model_name,

    "random_state":
        RANDOM_STATE

}


joblib.dump(

    model_package,

    MODEL_PATH

)


# FINAL MODEL

print(
    "\n" + "=" * 70
)

print(
    "FINAL MODEL"
)

print(
    "=" * 70
)

print(
    f"Selected model: "
    f"{best_model_name}"
)

print(
    "Selection criterion: F1-score"
)

print(
    f"Final F1-score: "
    f"{results_df.loc[best_index, 'F1_Score']:.4f}"
)

print(
    f"Final ROC-AUC: "
    f"{results_df.loc[best_index, 'ROC_AUC']:.4f}"
)

print(
    f"Final PR-AUC: "
    f"{results_df.loc[best_index, 'PR_AUC']:.4f}"
)

print(
    f"Saved model: "
    f"{MODEL_PATH}"
)

print(
    "\nMachine learning training completed successfully."
)