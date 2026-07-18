import sys
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# add src folder to path so the predict module can be imported
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

from predict import predict_url, get_domain, is_trusted_domain

app = FastAPI(
    title="BharatShield API",
    description="AI-based phishing URL detection - hybrid NLP + lexical ML "
                "with domain reputation and confidence calibration",
    version="1.0"
)


class ScanRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {
        "message": "BharatShield Phishing Detection API",
        "docs": "/docs",
        "usage": "POST /scan with {'url': 'https://example.com'}"
    }


@app.post("/scan")
def scan_url(request: ScanRequest):
    url = request.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

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
            "trusted_domain": is_trusted_domain(url),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")