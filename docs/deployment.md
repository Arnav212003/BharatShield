# Deployment Notes

## Local Streamlit App

```bash
python -m pip install -r requirements.txt
streamlit run app.py
```

## Local FastAPI Service

```bash
python -m pip install -r requirements-api.txt
uvicorn api:app --reload
```

Open `http://127.0.0.1:8000/docs` for the OpenAPI interface or call
`http://127.0.0.1:8000/health` to check model readiness.

## Docker API

```bash
docker build -t bharatshield .
docker run --rm -p 8000:8000 bharatshield
```

The image uses Python 3.11.9, installs API dependencies only, runs as UID 10001,
and includes an HTTP health check.

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

Other supported variables:

| Variable | Purpose |
| --- | --- |
| `BHARATSHIELD_LOG_LEVEL` | API log level; default is `WARNING` |
| `BHARATSHIELD_MODEL_DIR` | Alternate directory containing model artifacts |
| `BHARATSHIELD_DATA_PATH` | Alternate local CSV path used during training |

## Before Public Deployment

- Terminate HTTPS at a reverse proxy or managed platform.
- Configure rate limiting at the gateway. The application does not implement a
  distributed rate limiter.
- Add authentication if scans or results should not be public.
- Keep CORS restricted to known front-end origins.
- Send server logs to protected storage and avoid logging submitted content.
- Monitor `/health`, latency, memory, and error rates.
- Validate the model on legally sourced, recent, independent data.
- Do not market the service as a guaranteed security decision engine.
