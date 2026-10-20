# Deployment Notes

## Live demo

The Streamlit app is deployed on Streamlit Community Cloud:
<https://bharatshield-arnav.streamlit.app>

Streamlit Cloud installs `requirements.txt` and runs `app.py`. The app needs
only files that are in Git: `src/`, `ui/`, `config/trusted_domains.json` and
the trained files in `model/` (about 2 MB in total). The training data is not
needed at runtime. After pushing new models or a new `config/trusted_domains.json`,
the deployed app picks them up when it redeploys from the branch it is set to.

## Local Streamlit app

```bash
python -m pip install -r requirements.txt
streamlit run app.py
```

## Local FastAPI service

```bash
python -m pip install -r requirements-api.txt
uvicorn api:app --reload
```

Open `http://127.0.0.1:8000/docs` for the OpenAPI interface, or call
`http://127.0.0.1:8000/health` to check that the models loaded and to see the
active cutoffs (safe 0.50, phishing 0.80).

| Route | Input | Output |
| --- | --- | --- |
| `GET /health` | none | model status, model time, cutoffs, input limits |
| `POST /scan` | `{"url": "..."}` (max 2,048 characters) | result, risk score, ML score, reasons, rules applied, brand, trusted match |
| `POST /scan-message` | `{"message": "..."}` (max 3,000 characters) | status, risk score, reasons, signals, scanned links |

## Docker API

```bash
docker build -t bharatshield .
docker run --rm -p 8000:8000 bharatshield
```

The image uses Python 3.11.9, installs the API dependencies only, copies
`api.py`, `config/`, `model/` and `src/`, runs as UID 10001, and has an HTTP
health check.

## Configuration

Set allowed browser origins as a comma-separated value. When the variable is
empty, CORS middleware is not enabled.

PowerShell:

```powershell
$env:BHARATSHIELD_CORS_ORIGINS = "https://demo.example.com"
uvicorn api:app
```

Bash:

```bash
BHARATSHIELD_CORS_ORIGINS=https://demo.example.com uvicorn api:app
```

Other variables:

| Variable | Purpose |
| --- | --- |
| `BHARATSHIELD_LOG_LEVEL` | API log level; default is `WARNING` |
| `BHARATSHIELD_MODEL_DIR` | Other folder with model files (also where training writes) |

The trusted domain list, free hosting list and brand list are in
`config/trusted_domains.json`. Restart the app after editing it.

## Updating the model

```bash
python -m scripts.download_data
python -m scripts.build_dataset
python -m src.train_model
python -m unittest discover -s tests
```

Check `model/model_evaluation_report.csv` before replacing a deployed model. To
train into a separate folder first, set `BHARATSHIELD_MODEL_DIR`.

## Before a public production deployment

- Terminate HTTPS at a reverse proxy or managed platform.
- Configure rate limiting at the gateway. The application does not implement a
  rate limiter.
- Add authentication if scans or results should not be public.
- Keep CORS restricted to known front-end origins.
- Avoid logging submitted URLs and messages; they can contain personal data.
- Monitor `/health`, latency, memory and error rates.
- Retrain every few weeks with fresh phishing data; phishing URLs change fast.
- Do not market the service as a guaranteed security decision engine.
