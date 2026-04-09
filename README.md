# SentinelX Prototype

SentinelX is a working prototype of a Chrome Extension + FastAPI backend that detects, explains, and actively blocks browser threats in real time.

## Features Implemented

1. URL Risk Analyzer

- Detects HTTPS status
- Attempts domain-age lookup through WHOIS
- Checks trusted-domain allowlist
- Produces risk score (0-100)

2. Page Content Scanner

- Scans visible page text for phishing/scam patterns
- Tracks suspicious keywords like `login`, `urgent`, `free`, `download`

3. Download Protection

- Monitors browser download events
- Flags risky file types and suspicious source patterns
- Analyzes file metadata (`mime`, size, source/referrer)
- Auto-cancels unsafe downloads

4. Data Entry Protection

- Detects sensitive form inputs (`email`, `password`)
- Blocks unsafe form submissions and risky clicks
- Shows "SentinelX protected you" overlay for blocked actions

5. AI Explanation Engine

- Uses LLM for simple, non-technical explanation
- Includes top 2-3 reasons for risk decision

6. Active Shield / Hard Blocking

- Pre-navigation URL screening
- Hard-blocks high-risk pages to dedicated protection page
- Shows "I saved you from a threat" details

## Project Structure

- `extension/` Chrome extension (Manifest V3 + JS)
- `backend/` FastAPI API for risk scoring + explanation
- `demo/` Simulated pages: phishing, fake download, unsafe login, safe page

## Prerequisites

- Python 3.10+
- Google Chrome (or Chromium-based browser)

## Setup

### 1) Run backend API

From `backend/`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Optional but recommended for true LLM explanations
$env:OPENAI_API_KEY="your_api_key_here"
$env:OPENAI_MODEL="gpt-4o-mini"
# Optional for OpenAI-compatible providers
# $env:OPENAI_BASE_URL="https://api.openai.com/v1"

# NVIDIA-hosted OpenAI-compatible setup (recommended for this project)
# Either variable name works for the API key:
# $env:NVIDIA_API_KEY="your_nvidia_key_here"
# or
# $env:OPENAI_API_KEY="your_nvidia_key_here"
# Defaults already set in code:
# OPENAI_BASE_URL=https://integrate.api.nvidia.com/v1
# OPENAI_MODEL=sarvamai/sarvam-m

uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Health check:

- Open: `http://127.0.0.1:8000/health`

### 2) Serve demo pages

From `demo/` in a second terminal:

```powershell
python -m http.server 8081
```

Open:

- `http://127.0.0.1:8081/index.html`

### 3) Load extension in Chrome

1. Go to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` folder

## Demo Scenarios

Use links from `demo/index.html`:

- **Phishing simulation**: `phishing.html`
    - Contains urgency + credential keywords and sensitive fields
- **Fake download simulation**: `fake-download.html`
    - Includes `.exe` download lure
- **Unsafe login simulation**: `unsafe-login.html`
    - Sensitive form inputs on non-trusted context
- **Safe page**: `safe-page.html`
    - Minimal risk indicators

## How the Extension Works

- Background service worker screens URLs before/while navigation
- Content script scans page text + form/input patterns
- Content script intercepts risky clicks and form submissions
- Backend API scores URL/content/download and returns threat type + explanation
- Popup displays:
    - Risk score
    - Threat type
    - Simple AI explanation
    - Top reasons
- Protection events if SentinelX blocks a page/action/download
- Banner appears on medium-risk pages, hard block on high risk

## API Endpoints

- `POST /analyze-url`
- `POST /analyze-page`
- `POST /analyze-download`
- `POST /explain`
- `GET /health`

## Notes

- Domain age may be unavailable for some local/dev domains; SentinelX handles this gracefully.
- If backend is offline, extension falls back to local heuristic analysis.
- Without `OPENAI_API_KEY`, explanations still work via plain-language fallback (non-LLM).
