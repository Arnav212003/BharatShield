import os
import sys

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)


from predict import predict_url
from scam_message import analyze_scam_message
from security_layers import get_domain, is_trusted_domain


app = FastAPI(
    title="BharatShield API",
    description="Phishing URL and scam message detection API",
    version="1.0.0",
)


class URLRequest(BaseModel):
    url: str


class MessageRequest(BaseModel):
    message: str


@app.get("/")
def home():
    return {
        "name": "BharatShield",
        "message": "Fraud detection API is running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


@app.post("/scan")
def scan_url(request: URLRequest):
    url = request.url.strip()

    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty",
        )

    try:
        result, risk_score, reasons, confidence = predict_url(url)

        root_domain, full_domain = get_domain(url)

        return {
            "url": url,
            "result": result,
            "risk_score": risk_score,
            "confidence": confidence,
            "reasons": reasons,
            "root_domain": root_domain,
            "full_domain": full_domain,
            "trusted_domain": is_trusted_domain(url),
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="URL scan failed",
        )


@app.post("/scan-message")
def scan_message(request: MessageRequest):
    message = request.message.strip()

    if not message:
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty",
        )

    try:
        return analyze_scam_message(
            message,
            url_predictor=predict_url,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Message scan failed",
        )