import logging
import os
from datetime import datetime

import pandas as pd
import streamlit as st

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.abspath(
    os.getenv(
        "BHARATSHIELD_MODEL_DIR",
        os.path.join(BASE_DIR, "model"),
    )
)

logger = logging.getLogger("bharatshield.ui")


try:
    from src.predict import MAX_URL_LENGTH, predict_url, predict_url_details
    from src.scam_message import MAX_MESSAGE_LENGTH, analyze_scam_message
    from ui.style import load_css
except Exception:
    logger.exception("BharatShield could not start")
    st.error("Project files or model files could not be loaded.")
    st.stop()


st.set_page_config(
    page_title="BharatShield",
    page_icon="🛡️",
    layout="centered",
)

try:
    load_css()
except Exception:
    logger.warning("Custom CSS could not be loaded", exc_info=True)


def show_url_status(result):
    if result == "Safe URL":
        st.success("✅ Safe URL")
    elif result == "Suspicious URL":
        st.warning("⚠️ Suspicious URL")
    else:
        st.error("🚨 Phishing / Fraud URL Detected")


def show_message_status(status):
    if status == "Low Risk":
        st.success("✅ Low Risk Message")
    elif status == "Suspicious":
        st.warning("⚠️ Suspicious Message")
    else:
        st.error("🚨 Likely Fraud Message")


def show_metrics(risk_score, status, score_certainty):
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Risk Score",
            f"{risk_score}%",
            help="Project decision score; it is not a guaranteed probability.",
        )

    with col2:
        st.metric("Status", status)

    with col3:
        st.metric(
            "Score Certainty",
            f"{score_certainty}%",
            help=(
                "Heuristic based on distance from the decision cutoffs and, "
                "for URLs, agreement between the two models."
            ),
        )


def build_url_analysis(prediction):
    features = prediction["features"]
    explicit_scheme = prediction["explicit_scheme"]

    return {
        "Root Domain": prediction["root_domain"],
        "Full Domain": prediction["full_domain"],
        "URL Length": features["URL Length"],
        "Domain Length": features["Domain Length"],
        "Explicit Scheme": explicit_scheme.upper() if explicit_scheme else "Not provided",
        "Explicit HTTPS": "Yes" if features["HTTPS"] == 1 else "No",
        "Suspicious Keyword": "Yes" if features["Suspicious Keyword"] == 1 else "No",
        "IP Address Used": "Yes" if features["IP Address"] == 1 else "No",
        "Short URL": "Yes" if features["Short URL"] == 1 else "No",
        "Suspicious TLD": "Yes" if features["Suspicious TLD"] == 1 else "No",
        "Query Parameters": "Yes" if features["Has Query"] == 1 else "No",
        "Subdomain Count": features["Subdomain Count"],
        "Hyphen In Domain": "Yes" if features["Hyphen In Domain"] == 1 else "No",
        "Digit In Domain": "Yes" if features["Digit In Domain"] == 1 else "No",
        "Static Trusted List Match": "Yes" if prediction["trusted_domain"] else "No",
    }


if "url_history" not in st.session_state:
    st.session_state.url_history = []

if "message_history" not in st.session_state:
    st.session_state.message_history = []


st.markdown(
    '<div class="title">🛡️ BharatShield</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">Fraud Risk Screening Project</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="tagline">'
    'Phishing URL Detection • Rule-Based Message Screening • Readable Risk Reasons'
    '</div>',
    unsafe_allow_html=True,
)


url_tab, message_tab = st.tabs([
    "🔗 URL Scanner",
    "💬 Scam Message Scanner",
])


with url_tab:
    st.subheader("Phishing URL Detection")

    url = st.text_input(
        "Enter URL",
        placeholder="https://example.com",
        max_chars=MAX_URL_LENGTH,
        key="url_input",
    )

    if st.button(
        "Scan URL",
        width="stretch",
        key="scan_url",
    ):
        url = url.strip()

        if not url:
            st.warning("Enter a URL first.")

        else:
            try:
                with st.spinner("Scanning URL..."):
                    prediction = predict_url_details(url)

                result = prediction["result"]
                risk_score = prediction["risk_score"]
                reasons = prediction["reasons"]
                score_certainty = prediction["score_certainty"]

                st.markdown("### Scan Result")

                show_metrics(
                    risk_score,
                    result,
                    score_certainty,
                )

                st.progress(risk_score / 100)

                show_url_status(result)

                st.markdown("### URL Analysis")

                analysis = build_url_analysis(prediction)

                analysis_df = pd.DataFrame(
                    analysis.items(),
                    columns=["Analysis Point", "Value"],
                )

                st.dataframe(
                    analysis_df,
                    width="stretch",
                    hide_index=True,
                )

                st.markdown("### Detection Reasons")

                for reason in reasons:
                    st.write("•", reason)

                st.session_state.url_history.append({
                    "Time": datetime.now().strftime("%H:%M:%S"),
                    "URL": url,
                    "Risk Score": risk_score,
                    "Score Certainty": score_certainty,
                    "Result": result,
                })

            except ValueError as error:
                st.warning(str(error))

            except Exception:
                logger.exception("URL scan failed")
                st.error("URL scanning failed.")


    if st.session_state.url_history:
        st.markdown("### Recent URL Scans")

        url_history_df = pd.DataFrame(
            st.session_state.url_history
        )

        st.dataframe(
            url_history_df,
            width="stretch",
            hide_index=True,
        )

        col1, col2 = st.columns(2)

        with col1:
            if st.button(
                "Clear URL History",
                width="stretch",
            ):
                st.session_state.url_history = []
                st.rerun()

        with col2:
            csv_data = url_history_df.to_csv(
                index=False
            ).encode("utf-8")

            st.download_button(
                "Download URL Report",
                data=csv_data,
                file_name="bharatshield_url_report.csv",
                mime="text/csv",
                width="stretch",
            )


with message_tab:
    st.subheader("OTP & Scam Message Detection")

    st.caption(
        "Paste an SMS, WhatsApp message, or email text. "
        "Do not paste a real OTP that is currently active."
    )

    message = st.text_area(
        "Paste message",
        height=160,
        max_chars=MAX_MESSAGE_LENGTH,
        placeholder=(
            "Example: Your SBI KYC has expired. "
            "Verify immediately at sbi-update.xyz and enter your OTP."
        ),
    )

    if st.button(
        "Scan Message",
        width="stretch",
        key="scan_message",
    ):
        message = message.strip()

        if not message:
            st.warning("Paste a message first.")

        else:
            try:
                with st.spinner("Analyzing message..."):
                    result = analyze_scam_message(
                        message,
                        url_predictor=predict_url,
                    )

                risk_score = result["risk_score"]
                status = result["status"]
                score_certainty = result["score_certainty"]

                st.markdown("### Scan Result")

                show_metrics(
                    risk_score,
                    status,
                    score_certainty,
                )

                st.progress(risk_score / 100)

                show_message_status(status)

                st.markdown("### Detection Reasons")

                for reason in result["reasons"]:
                    st.write("•", reason)

                requested_items = result["sensitive_items_requested"]

                if requested_items:
                    st.markdown("### Sensitive Information Requested")

                    st.write(
                        ", ".join(requested_items)
                    )

                urls = result["urls"]

                if urls:
                    st.markdown("### Links Found")

                    for url_found in urls:
                        st.code(url_found)

                url_results = result["url_results"]

                if url_results:
                    st.markdown("### Embedded Link Analysis")

                    for item in url_results:
                        url_value = item.get("url", "Unknown URL")

                        with st.expander(url_value):
                            if "error" in item:
                                st.warning(
                                    "This link could not be scanned."
                                )
                            else:
                                st.write(
                                    "Risk Score:",
                                    f'{item["risk_score"]}%'
                                )

                                st.write(
                                    "Result:",
                                    item["result"]
                                )

                                if item.get("score_certainty") is not None:
                                    st.write(
                                        "Score Certainty:",
                                        f'{item["score_certainty"]}%'
                                    )

                                if item.get("reasons"):
                                    st.write("Reasons:")

                                    for reason in item["reasons"]:
                                        st.write("•", reason)

                st.session_state.message_history.append({
                    "Time": datetime.now().strftime("%H:%M:%S"),
                    "Risk Score": risk_score,
                    "Score Certainty": score_certainty,
                    "Status": status,
                    "Links Found": len(urls),
                })

            except ValueError as error:
                st.warning(str(error))

            except Exception:
                logger.exception("Message scan failed")
                st.error("Message scanning failed.")


    if st.session_state.message_history:
        st.markdown("### Recent Message Scans")

        message_history_df = pd.DataFrame(
            st.session_state.message_history
        )

        st.dataframe(
            message_history_df,
            width="stretch",
            hide_index=True,
        )

        if st.button(
            "Clear Message History",
            width="stretch",
        ):
            st.session_state.message_history = []
            st.rerun()


st.markdown("---")


with st.expander("📊 Model Analytics"):
    report_path = os.path.join(
        MODEL_DIR,
        "model_evaluation_report.csv",
    )

    lexical_cm = os.path.join(
        MODEL_DIR,
        "confusion_matrix_lexical.png",
    )

    hybrid_cm = os.path.join(
        MODEL_DIR,
        "confusion_matrix_hybrid.png",
    )

    final_cm = os.path.join(
        MODEL_DIR,
        "confusion_matrix_final.png",
    )

    feature_importance = os.path.join(
        MODEL_DIR,
        "feature_importance.png",
    )

    reliability_curve = os.path.join(
        MODEL_DIR,
        "reliability_curve.png",
    )

    if os.path.exists(report_path):
        st.markdown("### Evaluation Report")

        report = pd.read_csv(report_path)

        st.dataframe(
            report,
            width="stretch",
            hide_index=True,
        )

    if os.path.exists(lexical_cm):
        st.markdown("### Lexical Model")

        st.image(
            lexical_cm,
            width="stretch",
        )

    if os.path.exists(hybrid_cm):
        st.markdown("### Hybrid Model")

        st.image(
            hybrid_cm,
            width="stretch",
        )

    if os.path.exists(final_cm):
        st.markdown("### Final Decision System")

        st.image(
            final_cm,
            width="stretch",
        )

    if os.path.exists(feature_importance):
        st.markdown("### Feature Importance")

        st.image(
            feature_importance,
            width="stretch",
        )

    if os.path.exists(reliability_curve):
        st.markdown("### Reliability Curve")

        st.image(
            reliability_curve,
            width="stretch",
        )

    if not any(
        os.path.exists(path)
        for path in [
            report_path,
            lexical_cm,
            hybrid_cm,
            final_cm,
            feature_importance,
            reliability_curve,
        ]
    ):
        st.info(
            "Model analytics are not available yet."
        )


with st.expander("ℹ️ About BharatShield"):
    st.write(
        "BharatShield detects phishing URLs and scam messages "
        "using URL machine learning, character-pattern analysis, a static "
        "trusted-domain list, and readable security rules."
    )

    st.write(
        "The URL engine combines lexical URL features with "
        "TF-IDF character patterns. The message scanner checks "
        "for OTP, PIN, password, payment, urgency, KYC, and "
        "social-engineering signals."
    )


st.caption(
    "BharatShield • URL Machine Learning • Rule-Based Message Screening"
)
