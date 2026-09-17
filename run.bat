@echo off

echo ==============================================
echo B207 Email Phishing Threat Analyzer
echo ==============================================
echo.

echo Installing required packages...
python -m pip install -r requirements.txt

echo.
echo Initialising database...
python -c "from src.database import initialize_database; initialize_database()"

echo.
if not exist "models\phishing_model.pkl" (
    echo Trained model not found.
    echo Starting data preprocessing...
    python src\data_preprocessing.py

    echo.
    echo Training machine learning models...
    python src\model_training.py
) else (
    echo Trained model found.
)

echo.
echo Starting Email Phishing Threat Analyzer...
echo.

python src\main.py

pause