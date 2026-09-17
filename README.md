# Email Phishing Threat Detection and Risk Analysis Using Machine Learning

## B207 Cyber Security – Individual Project

A Python-based cybersecurity prototype that uses machine learning to classify email-security records as **Safe** or **Phishing** and provides probability-based risk assessment, SQLite database storage and reporting functionality.

---

## Project Overview

Phishing is a common cybersecurity threat in which deceptive emails are used to persuade users to interact with fraudulent or malicious content.

This project develops an **Email Phishing Threat Analyzer** using Python and scikit-learn. The system analyses extracted email-security indicators and applies supervised machine learning to classify records as either:

* **0 – Safe Email**
* **1 – Phishing Email**

The application provides a command-line interface (CLI) through which users can enter email-security feature values and receive:

* Safe or phishing classification
* Phishing probability
* Safe probability
* Risk level
* Persistent database storage
* Analysis history
* Detection statistics
* CSV export
* Summary reporting

The project was developed as part of the **B207 Cyber Security Individual Project**.

---

## Project Objectives

The main objectives are:

1. Develop a Python-based machine learning application for phishing detection.
2. Preprocess and validate extracted email-security features.
3. Compare Logistic Regression and Random Forest classification models.
4. Evaluate model performance using multiple classification metrics.
5. Implement probability-based phishing risk assessment.
6. Store analysis results using SQLite.
7. Provide analysis history and reporting functionality.
8. Validate the complete application through automated and real-record testing.

---

## Dataset

The project uses the Kaggle **Email Phishing Dataset** by Ethan Cratchley.

**Dataset:** Email Phishing Dataset
**Author:** Ethan Cratchley
**File used:** `email_phishing_data.csv`

**Kaggle source:**

https://www.kaggle.com/datasets/ethancratchley/email-phishing-dataset

The dataset contains numerical email-security indicators rather than raw email text.

### Dataset Features

| Feature               | Description                             |
| --------------------- | --------------------------------------- |
| `num_words`           | Number of words in the email            |
| `num_unique_words`    | Number of unique words                  |
| `num_stopwords`       | Number of stopwords                     |
| `num_links`           | Number of links                         |
| `num_unique_domains`  | Number of unique domains                |
| `num_email_addresses` | Number of email addresses               |
| `num_spelling_errors` | Number of spelling errors               |
| `num_urgent_keywords` | Number of urgent keywords               |
| `label`               | Target variable: 0 = Safe, 1 = Phishing |

### Dataset Processing

The original dataset contained:

* **524,846 records**
* **9 columns**
* **319,794 exact duplicate records**

After duplicate removal:

* **205,052 records**
* **198,971 Safe records (97.03%)**
* **6,081 Phishing records (2.97%)**

No missing values or negative feature values were identified in the cleaned dataset.

A `log1p` transformation was applied to the predictor variables before model development.

A stratified train-test split produced:

* **164,041 training records**
* **41,011 testing records**

### Important Dataset Limitation

The selected dataset provides **pre-extracted numerical email-security features**. It does not contain raw email text or complete email headers.

Therefore, this implementation analyses the supplied security indicators rather than independently parsing raw emails or extracting NLP features from email text.

---

## Machine Learning Approach

Two supervised classification algorithms were evaluated:

### 1. Logistic Regression

Logistic Regression was used as a linear classification baseline.

### 2. Random Forest

Random Forest was used as an ensemble model capable of modelling nonlinear relationships between the extracted email-security features.

Both models were implemented using scikit-learn pipelines with feature scaling and classification.

### Cross-Validation

A **5-fold Stratified Cross-Validation** approach was used while maintaining class proportions across folds.

The experiment used:

```text
random_state = 42
```

for reproducibility.

---

## Model Evaluation

The models were evaluated using:

* Accuracy
* Precision
* Recall
* F1-score
* ROC-AUC
* PR-AUC

F1-score was particularly important because the dataset contains substantial class imbalance.

### Test Set Results

| Metric    | Logistic Regression | Random Forest |
| --------- | ------------------: | ------------: |
| Accuracy  |              63.79% |    **87.84%** |
| Precision |               6.10% |    **13.46%** |
| Recall    |          **77.96%** |        57.15% |
| F1-score  |              11.32% |    **21.79%** |
| ROC-AUC   |              0.7717 |    **0.8442** |
| PR-AUC    |              0.1154 |    **0.2538** |

Random Forest was selected as the final model because it achieved the higher F1-score, together with stronger ROC-AUC and PR-AUC performance.

The results also demonstrate that the prototype still has important limitations, particularly its relatively low phishing Precision and the presence of both false positives and false negatives.

---

## Random Forest Confusion Matrix

The final Random Forest model produced:

|                     | Predicted Safe | Predicted Phishing |
| ------------------- | -------------: | -----------------: |
| **Actual Safe**     |         35,328 |              4,467 |
| **Actual Phishing** |            521 |                695 |

Therefore:

* True Negatives = **35,328**
* True Positives = **695**
* False Positives = **4,467**
* False Negatives = **521**

The confusion matrix demonstrates the practical trade-off between detecting phishing emails and avoiding unnecessary false alarms.

---

## Risk Assessment

The application converts the model's phishing probability into an application-level risk classification.

| Phishing Probability | Risk Level |
| -------------------- | ---------- |
| ≥ 70%                | HIGH       |
| 40% – <70%           | MEDIUM     |
| <40%                 | LOW        |

These thresholds are **manually defined application-level thresholds** and are not learned automatically by the machine learning model.

They can be calibrated or optimised in future versions.

---

## Application Functionality

The command-line application provides the following options:

```text
1. Analyse Email Features
2. View Analysis History
3. View Detection Statistics
4. Export Analysis Report
5. Generate Summary Report
6. Exit
```

### Example Prediction

A real phishing dataset record with the following feature values:

```text
num_words             = 87
num_unique_words      = 67
num_stopwords         = 24
num_links             = 3
num_unique_domains    = 3
num_email_addresses   = 2
num_spelling_errors   = 14
num_urgent_keywords   = 0
```

was classified as:

```text
Prediction           : PHISHING
Phishing Probability : 87.83%
Safe Probability     : 12.17%
Risk Level           : HIGH
```

The result was also stored in the SQLite database.

---

## Database Integration

SQLite is used for persistent storage.

Database file:

```text
database/phishing_analysis.db
```

Each analysis record stores:

* Analysis ID
* Timestamp
* Email-security feature values
* Prediction
* Phishing probability
* Safe probability
* Risk level

The database supports retrieval of previous analyses and calculation of detection statistics.

---

## Reporting

The system provides:

### Analysis History

Displays previously stored phishing analysis records.

### Detection Statistics

Reports:

* Total analyses
* Phishing detections
* Safe detections
* High-risk analyses
* Medium-risk analyses
* Low-risk analyses

### CSV Export

Analysis history can be exported to:

```text
results/analysis_history.csv
```

### Summary Report

A text-based summary can be generated at:

```text
results/summary_report.txt
```

---

## Project Structure

```text
B207_Email_Phishing_Threat_Analyzer/
│
├── data/
│   └── email_phishing_data.csv
│
├── models/
│   └── phishing_model.pkl
│
├── database/
│   └── phishing_analysis.db
│
├── results/
│   ├── figures/
│   ├── model_results.csv
│   ├── analysis_history.csv
│   └── summary_report.txt
│
├── src/
│   ├── data_preprocessing.py
│   ├── model_training.py
│   ├── prediction.py
│   ├── database.py
│   ├── reporting.py
│   ├── main.py
│   └── test_real_records.py
│
├── tests/
│   └── test_system.py
│
├── requirements.txt
├── README.md
├── run.bat
└── .gitignore
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Singh25181/B207_Email_Phishing_Threat_Analyzer.git
```

Move into the project directory:

```bash
cd B207_Email_Phishing_Threat_Analyzer
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv venv
```

Activate it:

```bash
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

The main Python libraries used are:

* pandas
* numpy
* scikit-learn
* matplotlib
* seaborn
* joblib

---

## Running the Project

From the project root directory:

```bash
python src/main.py
```

The application will initialise the database and provide the command-line menu.

---

## Training the Model

To preprocess the dataset and train the machine learning models:

```bash
python src/data_preprocessing.py
```

Then:

```bash
python src/model_training.py
```

The trained model is saved as:

```text
models/phishing_model.pkl
```

---

## Running Tests

Run the automated test suite using:

```bash
python -m unittest discover -s tests -v
```

The project was tested for core prediction, risk assessment and database functionality.

---

## Real-Record Validation

The project includes a real-record validation script:

```bash
python src/test_real_records.py
```

The validation tested both a safe and a phishing record from the cleaned dataset.

The demonstrated results were:

* Real Safe record → **SAFE**, 5.35% phishing probability
* Real Phishing record → **PHISHING**, 87.83% phishing probability

---

## Security and Design Considerations

This project is an academic cybersecurity prototype and should not be considered a complete production email-security gateway.

The current implementation does not provide:

* Raw email parsing
* Email header analysis
* Live mailbox integration
* URL reputation checking
* Domain reputation checking
* Attachment analysis
* Real-time automated email filtering

The model also produces false positives and false negatives, so predictions should not be treated as definitive security decisions.

---

## Limitations

The main limitations are:

1. Strong class imbalance in the dataset.
2. Low phishing Precision.
3. High number of false positives.
4. Presence of false negatives.
5. Pre-extracted rather than raw email features.
6. No live email integration.
7. No URL/domain reputation service.
8. No attachment analysis.
9. Manually defined risk thresholds.
10. CLI-based prototype rather than a production email gateway.

---

## Future Improvements

Future versions could incorporate:

* Raw email text and header extraction
* NLP-based feature extraction
* URL and domain reputation services
* Attachment analysis
* Hyperparameter optimisation
* Probability threshold calibration
* Explainable AI
* Web-based interface
* Real-time email integration
* Larger and more diverse datasets

---

## Technologies Used

| Technology   | Purpose                                |
| ------------ | -------------------------------------- |
| Python       | Application development                |
| Pandas       | Data processing                        |
| NumPy        | Numerical transformations              |
| Scikit-learn | Machine learning                       |
| Matplotlib   | Data visualisation                     |
| Seaborn      | Statistical visualisation              |
| Joblib       | Model persistence                      |
| SQLite       | Database storage                       |
| Git/GitHub   | Version control and project submission |

---

## Academic Project

**Module:** B207 Cyber Security
**Project Type:** Individual Project / Reassessment
**Project:** Email Phishing Threat Detection and Risk Analysis Using Machine Learning



