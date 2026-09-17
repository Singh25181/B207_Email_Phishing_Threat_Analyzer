# Email Phishing Threat Detection and Risk Analysis Using Machine Learning

B207 Cyber Security – Individual Project

This project is a Python-based email phishing detection prototype developed for the B207 Cyber Security individual project. It uses machine learning to classify email-security records as either safe or phishing and provides a probability-based risk assessment for each analysis.

The application also includes SQLite database storage, analysis history, detection statistics and report generation.

## Project Overview

Phishing emails can contain characteristics such as multiple links, unusual numbers of email addresses, spelling errors and urgent keywords. This project uses these extracted characteristics as input features for a machine learning classification system.

Two classification models were developed and compared:

- Logistic Regression
- Random Forest

The model with the stronger F1-score was selected for the final application.

The system can be operated through a command-line interface and stores completed analyses in an SQLite database.

## Dataset

The project uses the **Email Phishing Dataset** available from Kaggle:

https://www.kaggle.com/datasets/ethancratchley/email-phishing-dataset

Dataset file:

`email_phishing_data.csv`

The dataset contains the following features:

| Feature | Description |
|---|---|
| `num_words` | Number of words |
| `num_unique_words` | Number of unique words |
| `num_stopwords` | Number of stopwords |
| `num_links` | Number of links |
| `num_unique_domains` | Number of unique domains |
| `num_email_addresses` | Number of email addresses |
| `num_spelling_errors` | Number of spelling errors |
| `num_urgent_keywords` | Number of urgent keywords |
| `label` | 0 = Safe, 1 = Phishing |

The original dataset contained 524,846 records. After removing 319,794 exact duplicate records, 205,052 records remained.

The cleaned dataset contains:

- Safe: 198,971 (97.03%)
- Phishing: 6,081 (2.97%)

The dataset was checked for missing and negative values before modelling.

A `log1p` transformation was applied to the predictor variables. A stratified train-test split was then used, producing:

- Training records: 164,041
- Testing records: 41,011

### Dataset Note

The Kaggle dataset provides pre-extracted numerical features rather than raw email messages or complete email headers. Therefore, this project works with the supplied email-security indicators and does not perform raw email parsing.

## Machine Learning

The project uses Python and scikit-learn for model development.

The following models were evaluated:

### Logistic Regression

Used as a linear classification model and baseline for comparison.

### Random Forest

Used as an ensemble classification model to capture nonlinear relationships between the email-security features.

Both models were implemented using scikit-learn pipelines. A StandardScaler was included in the modelling pipeline and a 5-fold Stratified Cross-Validation procedure was used during evaluation.

The main evaluation measures were:

- Accuracy
- Precision
- Recall
- F1-score
- ROC-AUC
- PR-AUC

F1-score was used as an important model-selection measure because of the class imbalance in the dataset.

## Model Results

The test-set results were:

| Metric | Logistic Regression | Random Forest |
|---|---:|---:|
| Accuracy | 63.79% | 87.84% |
| Precision | 6.10% | 13.46% |
| Recall | 77.96% | 57.15% |
| F1-score | 11.32% | 21.79% |
| ROC-AUC | 0.7717 | 0.8442 |
| PR-AUC | 0.1154 | 0.2538 |

Random Forest was selected as the final model because it achieved the higher F1-score, as well as higher ROC-AUC and PR-AUC values.

The results also show that the model has limitations. In particular, the phishing Precision is relatively low and the model produces both false positives and false negatives.

## Confusion Matrix

The Random Forest model produced the following confusion matrix:

|  | Predicted Safe | Predicted Phishing |
|---|---:|---:|
| Actual Safe | 35,328 | 4,467 |
| Actual Phishing | 521 | 695 |

This gives:

- True Negatives: 35,328
- True Positives: 695
- False Positives: 4,467
- False Negatives: 521

The confusion matrix is included in the `results/figures` directory.

## Risk Assessment

The application converts the predicted phishing probability into three risk levels.

| Phishing Probability | Risk Level |
|---|---|
| 70% or above | HIGH |
| 40% to below 70% | MEDIUM |
| Below 40% | LOW |

These thresholds are manually defined within the application and are not learned by the machine learning model.

## Application

The main application is located in:

`src/main.py`

Run the application with:

```bash
python src/main.py