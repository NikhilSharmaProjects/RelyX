# RelyX Workflow Guide

This document explains how RelyX works end-to-end in simple workflow steps.

## 1) High-Level Architecture

RelyX has 2 main parts:

- Chrome extension (`extension/`)
- FastAPI backend (`backend/app/main.py`)

The extension observes browser activity and sends analysis requests.
The backend computes a deterministic risk score and returns a decision payload.

## 2) Main Components and Responsibilities

### Extension Service Worker (`extension/background.js`)

- Central orchestrator for:
    - URL checks
    - page checks
    - download checks
    - action blocking
    - temporary overrides
- Calls backend endpoints:
    - `POST /analyze-url`
    - `POST /analyze-page`
    - `POST /analyze-download`
- Caches URL reports for a short TTL.
- Stores latest results and events in `chrome.storage.local`.

### Content Script (`extension/content.js`)

- Runs on visited pages.
- Collects DOM/page signals (keywords, sensitive inputs, external form actions, suspicious download links, urgency/fear phrases, etc.).
- Sends page scan data to the service worker.
- Shows on-page warning UI and can block user actions when risk is high.

### Block Page (`extension/blocked.html` + `extension/blocked.js`)

- Full blocked destination view with risk details.
- Lets user leave the page, open new tab, or explicitly override.
- Override requires:
    - checkbox acknowledgment
    - confirmation dialog
- Sends `REQUEST_OVERRIDE` back to service worker.

### Popup UI (`extension/popup.js`)

- Displays current risk score, severity, confidence, reasons, and intel summary.
- Can trigger fresh analysis for current tab.
- Shows last protection/download events.

### Backend API (`backend/app/main.py`)

- Combines multiple signals into one score (`0-100`).
- Returns normalized report fields used by extension UI and policy logic.
- Uses external threat-intel sources when available; falls back to local heuristics if needed.

## 3) URL Navigation Workflow

1. User navigates to a page.
2. `background.js` receives `webNavigation.onBeforeNavigate`.
3. It calls URL analysis (`analyzeUrl`) and normalizes response.
4. If score is at/above block threshold and no active override:
    - it redirects tab to `blocked.html`.
5. Redirect includes query parameters:
    - target URL
    - score/threat/severity/confidence
    - reasons/explanation
    - blocked tab id (`tab_id`) for reliable override return.

## 4) Page Content Workflow

1. After page load completion (`tabs.onUpdated`), service worker requests page scan.
2. `content.js` returns page signals from the live DOM.
3. Service worker calls `/analyze-page` with URL + scan signals.
4. Service worker stores report and pushes result to content script.
5. Content script updates protection overlay/badge behavior.

## 5) Download Workflow

1. Browser creates a download (`downloads.onCreated`).
2. Service worker calls `/analyze-download`.
3. If score indicates dangerous download:
    - it cancels the download.
    - stores a protection event and download alert.
4. Otherwise it stores informational alert data for popup display.

## 6) Form/Action Blocking Workflow

1. Content script asks policy via `SHOULD_BLOCK_ACTION` before risky actions (for example form submit / risky download click).
2. Service worker checks current tab report and thresholds.
3. If action is unsafe:
    - blocks action
    - stores event
    - sends `SHOW_ACTION_BLOCK` back to content script.
4. If safe enough, action proceeds.

## 7) Blocked Page Override Workflow

1. User opens blocked page.
2. User must check acknowledgment checkbox.
3. User clicks override button and confirms dialog.
4. `blocked.js` sends `REQUEST_OVERRIDE` with:
    - `target_url`
    - `tab_id`
    - `explicit: true`
    - `acknowledged_disclaimer: true`
5. Service worker grants temporary host override (5 minutes).
6. Service worker updates that exact blocked tab back to target URL.

## 8) Temporary Override Rules

- Override is host-based and time-limited.
- Cleanup removes expired entries.
- While override is active, hard block for that host is bypassed.
- After TTL expiration, normal protection resumes.

## 9) Threshold and Decision Rules (Current Defaults)

- Hard page block threshold: `70`
- Form block threshold on risky context: `55`
- Action block threshold: `50`
- Download block (practical path): score `>= 60` or backend `should_block`

These values are enforced in extension policy logic and backend response handling.

## 10) Fallback Behavior

If backend calls or external intel sources fail:

- extension/backend use local heuristic fallback scoring
- confidence is reduced (typically `low`)
- protection still continues (fail-safe behavior, not fail-open)

## 11) Data Stored in Chrome Storage

Key items:

- `tabReports`: latest report per tab
- `urlCache`: URL analysis cache
- `temporaryOverrides`: active overrides per host
- `lastDownloadAlert`: latest download event
- `lastProtectionEvent`: latest block/protection event
- `trustedDomains`: trusted allowlist snapshot

## 12) How To Disable Continue-To-Site Feature

In `extension/blocked.js`, continue behavior is attached in:

- `setupSuspiciousSiteContinue()`

To disable user continuation, comment out this single line at the bottom:

```js
// setupSuspiciousSiteContinue();
```

Then reload extension in Chrome.

## 13) End-to-End Sequence Summary

1. Detect activity (navigate/load/download/action).
2. Gather URL + DOM signals.
3. Analyze via backend (or fallback).
4. Apply thresholds.
5. Enforce response:
    - allow
    - warn/overlay
    - block/redirect
    - cancel download
6. Optionally allow explicit temporary override.

## 14) Quick Testing Checklist

- Open safe page: should show low score / monitoring.
- Open phishing demo page: should block or warn with reasons.
- Try risky download link: should cancel at risky score.
- Try unsafe form submit: should block action on risky context.
- On blocked page override:
    - without checkbox -> denied
    - with checkbox + confirm -> continue allowed for override TTL
- After override TTL ends -> blocking should resume.
