import streamlit as st


def load_css():
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(
                135deg,
                #020617 0%,
                #0f172a 55%,
                #111827 100%
            );
        }

        .block-container {
            max-width: 1000px;
            padding-top: 2rem;
        }

        .title {
            text-align: center;
            font-size: 52px;
            font-weight: 800;
            color: white;
            margin-bottom: 4px;
        }

        .subtitle {
            text-align: center;
            font-size: 21px;
            color: #cbd5e1;
            margin-bottom: 8px;
        }

        .tagline {
            text-align: center;
            font-size: 15px;
            color: #94a3b8;
            margin-bottom: 30px;
        }

        [data-testid="stMetric"] {
            background: rgba(30, 41, 59, 0.75);
            border: 1px solid rgba(148, 163, 184, 0.18);
            padding: 16px;
            border-radius: 12px;
        }

        [data-testid="stDataFrame"] {
            border-radius: 10px;
            overflow: hidden;
        }

        .stButton > button {
            border-radius: 10px;
            font-weight: 600;
        }

        .stTextInput input,
        .stTextArea textarea {
            border-radius: 10px;
        }

        hr {
            border: none;
            height: 1px;
            background: rgba(148, 163, 184, 0.20);
            margin: 28px 0;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )