import streamlit as st


def load_css():
    st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #020617 0%, #0f172a 50%, #111827 100%);
        color: white;
    }

    .block-container {
        padding-top: 2rem;
        max-width: 1000px;
    }

    .title {
        font-size: 54px;
        font-weight: 900;
        color: #ffffff;
        text-align: center;
        margin-bottom: 5px;
    }

    .subtitle {
        font-size: 21px;
        color: #cbd5e1;
        text-align: center;
        margin-bottom: 10px;
    }

    .tagline {
        font-size: 15px;
        color: #94a3b8;
        text-align: center;
        margin-bottom: 35px;
    }

    .metric-card {
        padding: 22px;
        border-radius: 18px;
        background: rgba(30, 41, 59, 0.95);
        text-align: center;
        margin-bottom: 15px;
        border: 1px solid rgba(148, 163, 184, 0.18);
        box-shadow: 0px 8px 25px rgba(0,0,0,0.25);
    }

    .metric-card h3 {
        font-size: 22px;
        color: #e2e8f0;
    }

    .metric-card h2 {
        font-size: 38px;
        color: #ffffff;
    }

    .safe {
        background: rgba(20, 83, 45, 0.95);
        color: #4ade80;
        padding: 22px;
        border-radius: 16px;
        font-size: 25px;
        font-weight: 800;
        text-align: center;
        margin-top: 18px;
        border: 1px solid rgba(74, 222, 128, 0.35);
    }

    .suspicious {
        background: rgba(113, 63, 18, 0.95);
        color: #facc15;
        padding: 22px;
        border-radius: 16px;
        font-size: 25px;
        font-weight: 800;
        text-align: center;
        margin-top: 18px;
        border: 1px solid rgba(250, 204, 21, 0.35);
    }

    .danger {
        background: rgba(127, 29, 29, 0.95);
        color: #f87171;
        padding: 22px;
        border-radius: 16px;
        font-size: 25px;
        font-weight: 800;
        text-align: center;
        margin-top: 18px;
        border: 1px solid rgba(248, 113, 113, 0.35);
    }

    .reason-box {
        padding: 14px 18px;
        border-radius: 12px;
        background: rgba(15, 23, 42, 0.85);
        border-left: 4px solid #38bdf8;
        margin-bottom: 10px;
        font-size: 16px;
    }

    .safe-reason {
        border-left: 4px solid #22c55e;
    }

    .warning-reason {
        border-left: 4px solid #facc15;
    }

    .danger-reason {
        border-left: 4px solid #ef4444;
    }

    .info-card {
        padding: 18px;
        border-radius: 16px;
        background: rgba(15, 23, 42, 0.8);
        border: 1px solid rgba(148, 163, 184, 0.2);
        margin-top: 16px;
        margin-bottom: 16px;
    }

    .footer {
        text-align: center;
        color: #94a3b8;
        margin-top: 35px;
        padding-bottom: 20px;
        font-size: 14px;
    }

    hr {
        border: none;
        height: 1px;
        background: rgba(148, 163, 184, 0.25);
        margin: 30px 0;
    }

    .stButton > button {
        border-radius: 12px;
        height: 48px;
        font-weight: 700;
    }

    [data-testid="stDataFrame"] {
        border-radius: 14px;
        overflow: hidden;
    }
    </style>
    """, unsafe_allow_html=True)