# BharatShield 🛡️

AI-Based Phishing URL Detection System using Machine Learning and NLP.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red)
![Machine Learning](https://img.shields.io/badge/ML-Hybrid%20Detection-green)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Phishing%20Detection-black)

---

## 🔍 About BharatShield

BharatShield is an AI-powered phishing URL detection system designed to identify suspicious and fraudulent URLs using a hybrid machine learning approach.

The system combines:
- Lexical URL feature analysis
- NLP-based TF-IDF character n-gram detection
- Explainable risk scoring
- Trusted domain verification

Built with Indian users in mind, BharatShield focuses on detecting phishing attacks targeting banking, payment, and financial platforms.

---

## ✨ Features

✅ Hybrid NLP + Lexical ML Detection  
✅ Explainable Risk Scoring with Detection Reasons  
✅ Trusted Domain Verification  
✅ Real-Time URL Risk Analysis  
✅ Risk Score + Confidence Score  
✅ Suspicious Keyword Detection  
✅ Short URL Detection  
✅ IP Address Detection  
✅ Streamlit Dashboard UI  
✅ Scan History with CSV Export  
✅ Confusion Matrix & Feature Importance Analytics  

---

## 🧠 Detection Techniques

BharatShield analyzes URLs using multiple security indicators:

- URL Length Analysis
- Suspicious Keywords
- HTTPS Verification
- Suspicious TLD Detection
- Shortened URL Detection
- Subdomain Analysis
- Digit & Hyphen Detection
- IP-based URL Detection
- NLP Character Pattern Detection

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.8+ |
| Frontend/UI | Streamlit |
| ML Models | Random Forest + Logistic Regression |
| NLP | TF-IDF Character N-Grams |
| Data Processing | Pandas, Scipy |
| Visualization | Matplotlib, Seaborn |
| Model Storage | Joblib |

---

## 📁 Project Structure

```bash
BharatShield/
│
├── app.py
├── requirements.txt
├── README.md
│
├── data/
│   └── phishing.csv
│
├── model/
│   ├── phishing_model.pkl
│   ├── hybrid_model.pkl
│   ├── nlp_model.pkl
│   ├── confusion_matrix.png
│   └── feature_importance.png
│
├── src/
│   ├── features.py
│   ├── predict.py
│   ├── train_model.py
│   └── nlp_features.py
│
└── ui/
    └── style.py


## 🚀 Getting Started

git clone https://github.com/arnavsingh/BharatShield.git  
cd BharatShield  
pip install -r requirements.txt  

### 📂 Add Dataset
Place your dataset inside:

data/phishing.csv

Required columns:
url, label

Supported labels:
good/bad, safe/phishing, 0/1

### 🧠 Train the Model

python src/train_model.py

### ▶️ Run the App

streamlit run app.py