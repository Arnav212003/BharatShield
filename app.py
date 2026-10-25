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


def show_metrics(risk_score, status, third_label, third_value, third_help):
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Risk Score",
            f"{risk_score}%",
            help="Final decision score after rules. It is not a guaranteed probability.",
        )

    with col2:
        st.metric("Status", status)

    with col3:
        st.metric(third_label, third_value, help=third_help)


def yes_no(value):
    return "Yes" if value else "No"


def build_url_analysis(prediction):
    features = prediction["features"]
    scheme = prediction["explicit_scheme"]

    return {
        "Hostname": prediction["hostname"],
        "Registered Domain": prediction["root_domain"],
        "Scheme": scheme.upper() if scheme else "Not given",
        "Trusted List": prediction["trusted_match"] or "No",
        "Impersonated Brand": prediction["impersonated_brand"] or "None found",
        "Free Hosting Platform": prediction["free_hosting"] or "No",
        "URL Length": features["URL Length"],
        "Subdomain Count": features["Subdomain Count"],
        "Path Depth": features["Path Depth"],
        "Query Parameters": features["Query Parameters"],
        "Phishing Keywords": features["Keyword Count"],
        "IP Address Used": yes_no(features["IP Address"]),
        "Suspicious TLD": yes_no(features["Suspicious TLD"]),
        "Gradient Boosting Score": f"{prediction['lexical_risk'] * 100:.1f}%",
        "Logistic Regression Score": f"{prediction['hybrid_risk'] * 100:.1f}%",
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
    '<div class="subtitle">Phishing and Scam Screening for Indian Users</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="tagline">'
    'URL Machine Learning • Brand Impersonation Checks • Scam Message Rules'
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

                st.markdown("### Scan Result")

                show_url_status(result)

                if prediction["trusted_match"]:
                    st.caption("✔️ Trusted website")

                show_metrics(
                    risk_score,
                    result,
                    "ML Score",
                    f"{prediction['ml_risk_score']}%",
                    "Score from the two URL models before the fixed rules are applied.",
                )

                st.progress(risk_score / 100)

                if prediction["impersonated_brand"]:
                    st.error(
                        f"This link uses the name '{prediction['impersonated_brand']}' "
                        "but is not that company's official website."
                    )

                st.markdown("### Why")

                for reason in prediction["reasons"]:
                    st.write("•", reason)

                st.markdown("### URL Analysis")

                analysis_df = pd.DataFrame(
                    build_url_analysis(prediction).items(),
                    columns=["Analysis Point", "Value"],
                )
                analysis_df["Value"] = analysis_df["Value"].astype(str)

                st.dataframe(
                    analysis_df,
                    width="stretch",
                    hide_index=True,
                )

                st.session_state.url_history.append({
                    "Time": datetime.now().strftime("%H:%M:%S"),
                    "URL": url,
                    "Risk Score": risk_score,
                    "ML Score": prediction["ml_risk_score"],
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
            "Example: Aapka bijli connection aaj raat kat jayega. "
            "Turant 98XXXXXXXX par call karein."
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
                scam_signals = [
                    signal
                    for signal in result["signals"]
                    if signal != "contains_link"
                ]

                st.markdown("### Scan Result")

                show_message_status(status)

                show_metrics(
                    risk_score,
                    status,
                    "Scam Signals",
                    str(len(scam_signals)),
                    "Number of different scam patterns found in the message.",
                )

                st.progress(risk_score / 100)

                st.markdown("### Why")

                for reason in result["reasons"]:
                    st.write("•", reason)

                requested_items = result["sensitive_items_requested"]

                if requested_items:
                    st.markdown("### Sensitive Information Requested")
                    st.write(", ".join(requested_items))

                url_results = result["url_results"]

                if url_results:
                    st.markdown("### Links Found")

                    for item in url_results:
                        with st.expander(item.get("url", "Unknown URL")):
                            if "error" in item:
                                st.warning("This link could not be scanned.")
                            else:
                                st.write("Result:", item["result"])
                                st.write("Risk Score:", f'{item["risk_score"]}%')

                                for reason in item.get("reasons") or []:
                                    st.write("•", reason)

                st.session_state.message_history.append({
                    "Time": datetime.now().strftime("%H:%M:%S"),
                    "Risk Score": risk_score,
                    "Status": status,
                    "Scam Signals": len(scam_signals),
                    "Links Found": len(result["urls"]),
                })

            except ValueError as error:
                st.warning(str(error))

            except Exception:
                logger.exception("Message scan failed")
                st.error("Message scanning failed.")


    if st.session_state.message_history:
        st.markdown("### Recent Message Scans")

        st.dataframe(
            pd.DataFrame(st.session_state.message_history),
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
    report_path = os.path.join(MODEL_DIR, "model_evaluation_report.csv")

    images = [
        ("Final System on the External Test", "confusion_matrix_external.png"),
        ("Final System on the Internal Test", "confusion_matrix_internal.png"),
        ("Feature Importance", "feature_importance.png"),
        ("Reliability Curve", "reliability_curve.png"),
    ]

    found_any = False

    if os.path.exists(report_path):
        found_any = True
        st.markdown("### Evaluation Report")
        st.caption(
            "External = phishing first seen after the training cutoff date, "
            "from websites the model never saw in training."
        )
        st.dataframe(
            pd.read_csv(report_path),
            width="stretch",
            hide_index=True,
        )

    for title, file_name in images:
        path = os.path.join(MODEL_DIR, file_name)

        if os.path.exists(path):
            found_any = True
            st.markdown(f"### {title}")
            st.image(path, width="stretch")

    if not found_any:
        st.info("Model analytics are not available yet.")


with st.expander("ℹ️ About BharatShield"):
    st.write(
        "The URL scanner uses two machine learning models (gradient boosted "
        "trees on URL structure and a logistic regression on character patterns), "
        "then a few fixed rules for brand impersonation, IP addresses, "
        "redirects, short links, and free hosting platforms."
    )

    st.write(
        "The message scanner uses readable rules for OTP and PIN requests, "
        "KYC and account threats, fake electricity disconnection, lottery, "
        "parcel, 'digital arrest', job, investment, and loan scams. Links in "
        "the message are checked with the URL scanner."
    )

    st.write(
        "This is a student project and a second opinion, not a guarantee. "
        "When in doubt, open the official app or call the official number."
    )


st.caption(
    "BharatShield • URL Machine Learning • Rule-Based Message Screening"
)
