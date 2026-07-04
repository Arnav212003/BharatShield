import sys
import os
from datetime import datetime

import streamlit as st
import pandas as pd


# ----------------------------
# Project paths
# ----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
MODEL_DIR = os.path.join(BASE_DIR, "model")

# Add src folder to Python path
if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)


# ----------------------------
# Page config
# ----------------------------
st.set_page_config(
    page_title="BharatShield",
    page_icon="🛡️",
    layout="centered"
)


# ----------------------------
# Project imports
# ----------------------------
try:
    from predict import predict_url, get_domain, is_trusted_domain
    from features import extract_features
    from ui.style import load_css

except Exception as e:
    st.error("Project files or model files could not be loaded.")
    st.exception(e)
    st.stop()


# ----------------------------
# Load UI CSS
# ----------------------------
try:
    load_css()
except Exception as e:
    st.warning("Custom CSS could not be loaded.")
    st.exception(e)


# ----------------------------
# Helper: status config
# ----------------------------
def get_status_config(risk_score):
    if risk_score < 35:
        return {
            "status": "Safe",
            "status_html": '<div class="safe">✅ Safe URL</div>',
            "reason_class": "safe-reason",
            "reason_icon": "✅",
            "explanation": (
                "This URL looks safe based on the current layered phishing detection system."
            )
        }

    if risk_score < 70:
        return {
            "status": "Suspicious",
            "status_html": '<div class="suspicious">⚠️ Suspicious URL</div>',
            "reason_class": "warning-reason",
            "reason_icon": "⚠️",
            "explanation": (
                "This URL contains some suspicious patterns. Avoid entering passwords, "
                "OTPs, banking details, or personal information."
            )
        }

    return {
        "status": "Phishing",
        "status_html": '<div class="danger">🚨 Phishing / Fraud URL Detected</div>',
        "reason_class": "danger-reason",
        "reason_icon": "🚨",
        "explanation": (
            "This URL shows high-risk phishing patterns. Do not open it or share "
            "sensitive information."
        )
    }


# ----------------------------
# Header
# ----------------------------
st.markdown(
    '<div class="title">🛡️ BharatShield</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">AI-Based Phishing URL Detection System</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="tagline">Detect suspicious links using machine learning, risk scoring, and explainable URL analysis.</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="tagline">Model Type: Hybrid NLP + Lexical ML + Domain Reputation + Confidence Calibration</div>',
    unsafe_allow_html=True
)


# ----------------------------
# Session state
# ----------------------------
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []


# ----------------------------
# Input section
# ----------------------------
url = st.text_input(
    "🔗 Enter URL to scan",
    placeholder="Example: https://google.com or http://secure-bank-login123.xyz/verify-account"
)

scan_button = st.button("🚀 Scan URL", use_container_width=True)


# ----------------------------
# Scan logic
# ----------------------------
if scan_button:
    input_url = url.strip()

    if not input_url:
        st.warning("Please enter a URL first.")
        st.stop()

    with st.spinner("Scanning URL with BharatShield AI..."):
        try:
            result, risk_score, reasons, confidence = predict_url(input_url)
        except Exception as e:
            st.error("URL scanning failed. Please check model files and feature extraction code.")
            st.exception(e)
            st.stop()

    status_config = get_status_config(risk_score)

    status = status_config["status"]
    status_html = status_config["status_html"]
    reason_class = status_config["reason_class"]
    reason_icon = status_config["reason_icon"]
    explanation = status_config["explanation"]

    st.markdown("## Security Scan Result")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>Risk Score</h3>
            <h2>{risk_score}%</h2>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <h3>Status</h3>
            <h2>{status}</h2>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <h3>Confidence</h3>
            <h2>{confidence}%</h2>
        </div>
        """, unsafe_allow_html=True)

    st.progress(risk_score / 100)
    st.markdown(status_html, unsafe_allow_html=True)

    # ----------------------------
    # Risk explanation
    # ----------------------------
    st.markdown("### Risk Level Explanation")

    st.markdown(f"""
    <div class="info-card">
        {explanation}
    </div>
    """, unsafe_allow_html=True)

    # ----------------------------
    # Current URL Analysis
    # ----------------------------
    st.markdown("### Current URL Analysis")

    try:
        current_features = extract_features(input_url)
        root_domain, full_domain = get_domain(input_url)

        analysis_data = {
            "Root Domain": root_domain,
            "Full Domain": full_domain,
            "URL Length": current_features[0],
            "Domain Length": current_features[1],
            "HTTPS Used": "Yes" if current_features[12] == 1 else "No",
            "Suspicious Keyword": "Yes" if current_features[14] == 1 else "No",
            "IP Address Used": "Yes" if current_features[15] == 1 else "No",
            "Short URL": "Yes" if current_features[16] == 1 else "No",
            "Suspicious TLD": "Yes" if current_features[17] == 1 else "No",
            "Query Parameters": "Yes" if current_features[18] == 1 else "No",
            "Subdomain Count": current_features[19],
            "Hyphen In Domain": "Yes" if current_features[20] == 1 else "No",
            "Digit In Domain": "Yes" if current_features[21] == 1 else "No",
            "Domain Reputation Match": "Yes" if is_trusted_domain(input_url) else "No",
            "Model Used": "Hybrid NLP + Lexical ML",
            "Additional Layer": "Domain Reputation + Confidence Calibration"
        }

        analysis_df = pd.DataFrame(
            list(analysis_data.items()),
            columns=["Analysis Point", "Value"]
        )

        st.dataframe(
            analysis_df,
            use_container_width=True,
            hide_index=True
        )

    except Exception as e:
        st.error("Current URL analysis failed.")
        st.exception(e)

    # ----------------------------
    # Detection reasons
    # ----------------------------
    st.markdown("### Detection Reasons")

    for reason in reasons:
        st.markdown(f"""
        <div class="reason-box {reason_class}">
            {reason_icon} {reason}
        </div>
        """, unsafe_allow_html=True)

    # ----------------------------
    # Save scan history
    # ----------------------------
    st.session_state.scan_history.append({
        "Time": datetime.now().strftime("%H:%M:%S"),
        "URL": input_url,
        "Risk Score": risk_score,
        "Confidence": confidence,
        "Status": status
    })


# ----------------------------
# Scan history section
# ----------------------------
if st.session_state.scan_history:
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("## Recent Scan History")

    df = pd.DataFrame(st.session_state.scan_history)

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )

    col_a, col_b = st.columns(2)

    with col_a:
        if st.button("🧹 Clear History", use_container_width=True):
            st.session_state.scan_history = []
            st.rerun()

    with col_b:
        csv_data = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="⬇️ Download Report CSV",
            data=csv_data,
            file_name="bharatshield_scan_history.csv",
            mime="text/csv",
            use_container_width=True
        )


# ----------------------------
# Extra sections
# ----------------------------
st.markdown("<hr>", unsafe_allow_html=True)


with st.expander("📊 View Model Analytics"):
    evaluation_report_path = os.path.join(MODEL_DIR, "model_evaluation_report.csv")

    confusion_matrix_path = os.path.join(MODEL_DIR, "confusion_matrix.png")
    confusion_matrix_lexical_path = os.path.join(MODEL_DIR, "confusion_matrix_lexical.png")
    confusion_matrix_hybrid_path = os.path.join(MODEL_DIR, "confusion_matrix_hybrid.png")
    confusion_matrix_final_path = os.path.join(MODEL_DIR, "confusion_matrix_final.png")

    feature_importance_path = os.path.join(MODEL_DIR, "feature_importance.png")

    st.markdown("### Model Evaluation Report")

    if os.path.exists(evaluation_report_path):
        evaluation_df = pd.read_csv(evaluation_report_path)

        st.dataframe(
            evaluation_df,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("Model evaluation report not found. Run train_model.py first.")

    st.markdown("### Confusion Matrices")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Lexical Model")

        if os.path.exists(confusion_matrix_lexical_path):
            st.image(confusion_matrix_lexical_path, use_container_width=True)
        else:
            st.info("Lexical confusion matrix not found. Run train_model.py first.")

    with col2:
        st.markdown("#### Hybrid Model")

        if os.path.exists(confusion_matrix_hybrid_path):
            st.image(confusion_matrix_hybrid_path, use_container_width=True)
        else:
            st.info("Hybrid confusion matrix not found. Run train_model.py first.")

    st.markdown("#### Final Calibrated System")

    if os.path.exists(confusion_matrix_final_path):
        st.image(confusion_matrix_final_path, use_container_width=True)
    elif os.path.exists(confusion_matrix_path):
        st.image(confusion_matrix_path, use_container_width=True)
    else:
        st.info("Final calibrated confusion matrix not found. Run train_model.py first.")

    st.markdown("### Lexical Feature Importance")

    if os.path.exists(feature_importance_path):
        st.image(feature_importance_path, use_container_width=True)
    else:
        st.info("Feature importance image not found. Run train_model.py first.")


with st.expander("ℹ️ About BharatShield"):
    st.markdown("""
    <div class="info-card">
    BharatShield is an AI-powered phishing URL detection system built using Python, Streamlit, NLP, and Machine Learning.
    It follows a layered security architecture that combines raw ML scoring, lexical URL analysis,
    NLP-based TF-IDF features, domain reputation checking, confidence calibration, and explainable risk reasons.
    <br><br>
    The system analyzes domain length, HTTPS usage, suspicious keywords, IP address usage, shortened links,
    suspicious TLDs, subdomains, special characters, query parameters, and URL text patterns.
    </div>
    """, unsafe_allow_html=True)


# ----------------------------
# Footer
# ----------------------------
st.markdown(
    '<div class="footer">Built with Machine Learning • NLP • Python • Streamlit • BharatShield</div>',
    unsafe_allow_html=True
)