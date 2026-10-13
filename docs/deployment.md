# Deployment Notes

This project can be run locally, through Docker, or on a Python hosting platform. The simplest deployment target is the FastAPI API because it starts with one command and does not need a browser session.

## Local API

```bash
py -m pip install -r requirements.txt
uvicorn api:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Local Streamlit App

```bash
streamlit run app.py
```

## Docker API

Build the image:

```bash
docker build -t bharatshield .
```

Run the API:

```bash
docker run --rm -p 8000:8000 bharatshield
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Notes Before Public Deployment

- Keep model files inside the image or mount them from storage.
- Do not expose this as a final security product without more real-world testing.
- Add the real dataset source and license before submission.
- For a public demo, mention clearly that this is an educational fraud-detection project.
