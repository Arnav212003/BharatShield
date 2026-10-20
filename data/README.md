# Local Training Data

`phishing.csv` is intentionally ignored because the source and license of the
file used for the current model could not be verified.

To retrain BharatShield, place a legally obtained CSV at:

```text
data/phishing.csv
```

The first two columns must contain the URL and label. Supported safe labels
include `good`, `safe`, `legitimate`, `benign`, and `0`. Supported unsafe labels
include `bad`, `phishing`, `fraud`, `malicious`, `unsafe`, and `1`.

Update `data/provenance.json` only after confirming the original source and
license. Do not add a source based on a guess or a similar-looking dataset.
