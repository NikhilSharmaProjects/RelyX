# RelyX Real-Time Active Security System

RelyX is a Chrome Extension (Manifest V3) plus FastAPI backend that performs real-time multi-layer threat detection and active blocking.

## Core Security Capabilities

- Multi-layer URL intelligence:
    - Google Safe Browsing (phishing/malware reputation)
    - VirusTotal (URL reputation for page and download source)
    - PhishTank (phishing database checks)
    - WHOIS domain age checks
    - HTTPS and TLS certificate validation
    - URL pattern analysis (typosquatting, punycode, IP host, lure terms, risky TLD)

- Final deterministic risk score:
    - Score range: 0-100
    - Hard-block threshold: 70
    - Download auto-block threshold: 60
    - Form-block threshold on risky pages: 55

- Real-time active blocking:
    - Pre-navigation URL screening from service worker
    - Full-screen threat lock overlay when risk is high
    - Interaction lock (`pointer-events: none` on page content)
    - Download cancellation for suspicious files
    - Sensitive form submission blocking on unsafe pages
    - Explicit override required to proceed (5-minute temporary host override)

- AI explanation layer (non-decision role):
    - LLM receives structured signals and precomputed score
    - LLM outputs deterministic JSON-only explanation fields
    - LLM does not decide risk
    - NVIDIA OpenAI-compatible endpoint is the default provider

- Smart fallback mode:
    - If external APIs fail, RelyX falls back to heuristic multi-signal scoring
    - Confidence is explicitly set to `low`
    - Failure is never silent

## Project Structure

- `extension/`: Chrome extension files
- `backend/`: FastAPI threat engine
- `demo/`: test pages for phishing, fake download, unsafe login, safe scenarios

## Prerequisites

- Python 3.10+
- Google Chrome or Chromium browser

## Backend Setup

From `backend/`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Required for external intelligence integrations:
$env:GOOGLE_SAFE_BROWSING_API_KEY="YOUR_GOOGLE_SAFE_BROWSING_KEY"
$env:VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_KEY"
$env:PHISHTANK_API_KEY="YOUR_PHISHTANK_KEY"

# Optional WHOIS API (backend will fallback to python-whois if absent):
# $env:WHOIS_API_KEY="YOUR_WHOISXMLAPI_KEY"
# $env:WHOIS_API_URL="https://www.whoisxmlapi.com/whoisserver/WhoisService"

# Optional LLM explanation (deterministic structured output):
# $env:NVIDIA_API_KEY="YOUR_NVIDIA_API_KEY"
# $env:OPENAI_BASE_URL="https://integrate.api.nvidia.com/v1"
# $env:OPENAI_MODEL="sarvamai/sarvam-m"

uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Health check:

- Open `http://127.0.0.1:8000/health`

## Demo Pages

From `demo/` in a second terminal:

```powershell
python -m http.server 8081
```

Open:

- `http://127.0.0.1:8081/index.html`

## Extension Setup

1. Open `chrome://extensions/`
2. Enable Developer mode
3. Click Load unpacked
4. Select `extension/`

## Security Flow

1. Background service worker checks URL in real time.
2. Backend fuses API intel + WHOIS + TLS + pattern signals into score.
3. Content script collects DOM/NLP page signals for second-pass scoring.
4. If risk exceeds threshold:
    - page is hard-blocked to protected view, or
    - full-screen lock overlay is applied with interaction disabled.
5. Downloads and sensitive forms are actively blocked on unsafe pages.
6. User can only proceed through explicit override action.

## API Endpoints

- `POST /analyze-url`
- `POST /analyze-page`
- `POST /analyze-download`
- `POST /explain`
- `GET /health`

## Important Notes

- If threat-intel keys are missing, RelyX still runs in fallback mode but marks confidence as `low`.
- VirusTotal checks are performed on URL reputation (not binary file scanning in-browser).
- Domain age for private/local domains may be unavailable and is handled safely.
