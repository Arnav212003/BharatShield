import logging
import os
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.predict import (
    MAX_URL_LENGTH,
    get_model_info,
    predict_url,
    predict_url_details,
)
from src.scam_message import MAX_MESSAGE_LENGTH, analyze_scam_message

LOG_LEVEL = os.getenv("BHARATSHIELD_LOG_LEVEL", "WARNING").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.WARNING)
)
logger = logging.getLogger("bharatshield.api")


app = FastAPI(
    title="BharatShield API",
    description="Phishing URL and scam message detection API",
    version="1.0.0",
)


cors_origins = [
    origin.strip()
    for origin in os.getenv("BHARATSHIELD_CORS_ORIGINS", "").split(",")
    if origin.strip()
]

if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )


class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)


class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)


class HomeResponse(BaseModel):
    name: str
    message: str
    docs: str


class HealthResponse(BaseModel):
    status: Literal["ok"]
    model_ready: bool
    model_generated_at_utc: str | None
    safe_cutoff: float
    max_url_length: int
    max_message_length: int


class URLScanResponse(BaseModel):
    url: str
    result: str
    risk_score: int
    score_certainty: float
    reasons: list[str]
    root_domain: str
    full_domain: str
    trusted_domain: bool


class EmbeddedURLResult(BaseModel):
    url: str
    result: str | None = None
    risk_score: int | None = None
    score_certainty: float | None = None
    reasons: list[str] | None = None
    error: str | None = None


class MessageScanResponse(BaseModel):
    status: str
    risk_score: int
    score_certainty: float
    reasons: list[str]
    signals: list[str]
    sensitive_items_requested: list[str]
    urls: list[str]
    url_results: list[EmbeddedURLResult]


@app.get("/", response_model=HomeResponse)
def home():
    return {
        "name": "BharatShield",
        "message": "Fraud detection API is running",
        "docs": "/docs",
    }


@app.get("/health", response_model=HealthResponse)
def health():
    model_info = get_model_info()

    return {
        "status": "ok",
        "model_ready": model_info["ready"],
        "model_generated_at_utc": model_info["generated_at_utc"],
        "safe_cutoff": model_info["safe_cutoff"],
        "max_url_length": MAX_URL_LENGTH,
        "max_message_length": MAX_MESSAGE_LENGTH,
    }


@app.post("/scan", response_model=URLScanResponse)
def scan_url(request: URLRequest):
    url = request.url.strip()

    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty",
        )

    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"URL cannot be longer than {MAX_URL_LENGTH} characters",
        )

    try:
        details = predict_url_details(url)

        logger.info(
            "URL scan completed: result=%s risk_score=%s",
            details["result"],
            details["risk_score"],
        )

        return details

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        logger.exception("URL scan failed")

        raise HTTPException(
            status_code=500,
            detail="URL scan failed",
        ) from error


@app.post("/scan-message", response_model=MessageScanResponse)
def scan_message(request: MessageRequest):
    message = request.message.strip()

    if not message:
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty",
        )

    if len(message) > MAX_MESSAGE_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=(
                "Message cannot be longer than "
                f"{MAX_MESSAGE_LENGTH} characters"
            ),
        )

    try:
        result = analyze_scam_message(
            message,
            url_predictor=predict_url,
        )

        logger.info(
            "Message scan completed: status=%s risk_score=%s",
            result["status"],
            result["risk_score"],
        )

        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        logger.exception("Message scan failed")

        raise HTTPException(
            status_code=500,
            detail="Message scan failed",
        ) from error
