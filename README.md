# BharatShield 🛡️

BharatShield is an AI-based fraud detection system for detecting phishing URLs and suspicious scam messages.

It combines Machine Learning, NLP, URL security analysis, domain reputation, and explainable risk scoring.

## Features

- Phishing URL Detection
- OTP & Scam Message Detection
- Suspicious Link Analysis
- Risk Score and Confidence Score
- Explainable Detection Reasons
- Trusted Domain Verification
- Streamlit Dashboard
- FastAPI Support
- Model Evaluation and Confusion Matrix

## Tech Stack

Python, Streamlit, FastAPI, Scikit-learn, Pandas, TF-IDF, Random Forest, Logistic Regression, SciPy and Joblib.

## Detection Approach

BharatShield uses:

- Random Forest for lexical URL features
- Logistic Regression with lexical + TF-IDF features
- Domain reputation and rule-based risk calibration
- Scam-message analysis for OTP, PIN, CVV, KYC, urgency and suspicious links

If a scam message contains a URL, the URL is also scanned using the phishing detection model.

## Run

Install dependencies:

```bash
pip install -r requirements.txt

Start the application:

```bash
streamlit run app.py

Run the API:

```bash
uvicorn api:app --reload

Open API documentation:

```text
http://127.0.0.1:8000/docs


## Note

BharatShield is an educational fraud-detection project. The risk score should be treated as a warning signal, not as a guarantee.