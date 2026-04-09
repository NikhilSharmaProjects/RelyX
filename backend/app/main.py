# pyright: reportMissingImports=false
import asyncio
import os
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI
from pydantic import BaseModel, Field

app = FastAPI(title="RelyX API", version="0.2.0")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "sarvamai/sarvam-m")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://integrate.api.nvidia.com/v1")


def resolve_api_key() -> tuple[str, str]:
    nvidia_key = (os.getenv("NVIDIA_API_KEY", "") or "").strip()
    openai_key = (os.getenv("OPENAI_API_KEY", "") or "").strip()
    if nvidia_key:
        return nvidia_key, "NVIDIA_API_KEY"
    if openai_key:
        return openai_key, "OPENAI_API_KEY"
    return "", "none"


OPENAI_API_KEY, OPENAI_API_KEY_SOURCE = resolve_api_key()

DEFAULT_TRUSTED_DOMAINS = [
    "google.com",
    "microsoft.com",
    "github.com",
    "wikipedia.org",
    "cloudflare.com",
    "apple.com",
    "amazon.com",
    "openai.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

URL_SUSPICIOUS_TERMS = [
    "verify",
    "secure",
    "update",
    "login",
    "bonus",
    "gift",
    "wallet",
    "free",
    "download",
]

CONTENT_KEYWORD_WEIGHTS = {
    "login": 7,
    "verify": 9,
    "password": 8,
    "urgent": 10,
    "free": 5,
    "download": 6,
    "bank": 9,
    "wallet": 8,
    "reset": 7,
    "security alert": 10,
}


class URLRequest(BaseModel):
    url: str
    trusted_domains: List[str] = Field(default_factory=list)


class PageRequest(BaseModel):
    url: str
    page_text: str = ""
    matched_keywords: List[str] = Field(default_factory=list)
    keyword_hits: int = 0
    has_sensitive_inputs: bool = False
    suspicious_download_links: int = 0
    trusted_domains: List[str] = Field(default_factory=list)


class DownloadRequest(BaseModel):
    filename: str = ""
    source_url: str
    referrer: str = ""
    mime: str = ""
    total_bytes: int = 0
    final_url: str = ""
    trusted_domains: List[str] = Field(default_factory=list)


class ExplainRequest(BaseModel):
    url: Optional[str] = None
    risk_score: int
    threat_type: str
    reasons: List[str]


def parse_domain(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def is_trusted_domain(domain: str, trusted_domains: List[str]) -> bool:
    domain = (domain or "").lower()
    if not domain:
        return False
    for trusted in trusted_domains:
        trusted = trusted.lower().strip()
        if not trusted:
            continue
        if domain == trusted or domain.endswith(f".{trusted}"):
            return True
    return False


def get_domain_age_days(domain: str) -> Optional[int]:
    if not domain:
        return None

    try:
        import whois

        result = whois.whois(domain)
        creation_date = result.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None

        if creation_date is None:
            return None

        if isinstance(creation_date, str):
            # Best-effort parsing for non-datetime WHOIS responses.
            creation_date = datetime.fromisoformat(creation_date)

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        delta = datetime.now(timezone.utc) - creation_date
        return max(0, delta.days)
    except Exception:
        return None


def classify_url(url: str, trusted_domains: List[str]) -> dict:
    domain = parse_domain(url)
    reasons = []
    score = 0

    https_enabled = url.lower().startswith("https://")
    domain_age_days = get_domain_age_days(domain)
    trusted = is_trusted_domain(domain, trusted_domains)

    if trusted:
        score -= 40
        reasons.append("Domain is in RelyX trusted domain list.")

    if not https_enabled:
        score += 25
        reasons.append("Page is using HTTP instead of HTTPS.")

    if domain_age_days is not None:
        if domain_age_days < 30:
            score += 35
            reasons.append("Domain age is very new (under 30 days).")
        elif domain_age_days < 180:
            score += 18
            reasons.append("Domain age is relatively new (under 6 months).")
    else:
        score += 10
        reasons.append("Domain age could not be verified.")

    if domain.count(".") >= 3:
        score += 10
        reasons.append("URL contains many subdomains, which can be misleading.")

    if "xn--" in domain:
        score += 20
        reasons.append("Potential IDN homograph pattern found in the domain.")

    domain_text = f"{domain} {url.lower()}"
    matched_terms = [term for term in URL_SUSPICIOUS_TERMS if term in domain_text]
    if matched_terms:
        score += min(22, 6 + len(matched_terms) * 4)
        reasons.append("URL includes words commonly used in phishing lures.")

    return {
        "https": https_enabled,
        "domain": domain,
        "domain_age_days": domain_age_days,
        "is_trusted_domain": trusted,
        "url_score": min(100, max(0, score)),
        "url_reasons": reasons,
    }


def classify_content(page_text: str, keyword_hits: int, has_sensitive_inputs: bool, suspicious_download_links: int) -> dict:
    text = (page_text or "").lower()
    reasons = []
    score = 0

    weighted_hits = 0
    matched_keywords = []

    for keyword, weight in CONTENT_KEYWORD_WEIGHTS.items():
        occurrences = text.count(keyword)
        if occurrences > 0:
            weighted_hits += occurrences * weight
            matched_keywords.append(keyword)

    if keyword_hits > 0:
        weighted_hits = max(weighted_hits, keyword_hits * 4)

    if weighted_hits > 0:
        score += min(35, weighted_hits)
        reasons.append("Page text contains phishing/scam-related language patterns.")

    if has_sensitive_inputs:
        score += 15
        reasons.append("Sensitive input fields (email/password) detected on this page.")

    if suspicious_download_links > 0:
        score += min(30, 15 + suspicious_download_links * 5)
        reasons.append("Suspicious download links detected on the page.")

    combo_phishing = {"login", "verify", "urgent"}
    if combo_phishing.issubset(set(matched_keywords)):
        score += 12
        reasons.append("Combined urgency + credential language indicates likely phishing behavior.")

    return {
        "content_score": min(100, score),
        "content_reasons": reasons,
    }


def select_threat_type(total_score: int, has_sensitive_inputs: bool, suspicious_download_links: int) -> str:
    if suspicious_download_links > 0 and total_score >= 55:
        return "Malware / Fake Download"
    if has_sensitive_inputs and total_score >= 50:
        return "Unsafe Login / Credential Theft"
    if total_score >= 45:
        return "Phishing Suspicion"
    return "Likely Safe"


def generate_explanation(url: str, risk_score: int, threat_type: str, reasons: List[str]) -> str:
    top_reasons = reasons[:3]
    if not top_reasons:
        return "RelyX did not find strong indicators of malicious behavior on this page."

    reason_text = " ".join(top_reasons)
    return (
        f"RelyX classified this page as {threat_type} with a risk score of {risk_score}/100. "
        f"Key signals: {reason_text} "
        "Avoid entering sensitive information or downloading files unless you trust the source."
    )


def fallback_plain_explanation(threat_type: str, risk_score: int, reasons: List[str], blocked: bool = False) -> str:
    first = reasons[0] if reasons else "Risk signals were detected."
    if threat_type == "Likely Safe" and risk_score <= 20:
        return (
            f"This page currently looks safe (risk {risk_score}/100). "
            f"Signal observed: {first}. RelyX will keep monitoring in real time."
        )

    action = "blocked" if blocked else "flagged"
    return (
        f"RelyX {action} this activity ({threat_type}, risk {risk_score}/100). "
        f"Main reason: {first}. Avoid sharing passwords or running downloads unless you fully trust the source."
    )


def _llm_chat_completion(system_prompt: str, user_prompt: str) -> str:
    client = OpenAI(base_url=OPENAI_BASE_URL, api_key=OPENAI_API_KEY)
    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.25,
        top_p=1,
        max_tokens=220,
    )

    if not response.choices:
        return ""

    content = response.choices[0].message.content
    return content.strip() if content else ""


def _llm_rewrite_final(threat_type: str, risk_score: int, reasons: List[str], blocked: bool, target: str) -> str:
    client = OpenAI(base_url=OPENAI_BASE_URL, api_key=OPENAI_API_KEY)
    rewrite_prompt = (
        "Return ONLY final user-facing text. No analysis, no planning, no markdown, no labels. "
        "Write 70-100 words in simple language for non-technical users. "
        "Must include: what happened, why risky, what RelyX did, and confidence level."
    )
    context = (
        f"Target: {target}\n"
        f"Threat type: {threat_type}\n"
        f"Risk score: {risk_score}/100\n"
        f"Blocked: {blocked}\n"
        f"Reasons: {reasons[:3]}"
    )
    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": rewrite_prompt},
            {"role": "user", "content": context},
        ],
        temperature=0.1,
        top_p=1,
        max_tokens=180,
    )
    if not response.choices:
        return ""
    content = response.choices[0].message.content
    return content.strip() if content else ""


def extract_user_facing_text(raw_text: str) -> str:
    text = (raw_text or "").replace("\r", "\n")
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    if not lines:
        return ""

    blocked_starts = (
        "okay",
        "let's",
        "the user",
        "first,",
        "next,",
        "i need",
        "i should",
        "my response",
    )

    kept = []
    for line in lines:
        lower = line.lower()
        if lower.startswith(blocked_starts):
            continue
        if "the user wants" in lower or "i need to" in lower:
            continue
        kept.append(line)

    if not kept:
        return ""

    merged = " ".join(kept)
    merged = " ".join(merged.split())
    return merged[:650].rsplit(" ", 1)[0] + "..." if len(merged) > 650 else merged


def sanitize_llm_output(text: str, threat_type: str, risk_score: int, reasons: List[str], blocked: bool) -> tuple[str, bool]:
    cleaned = (text or "").strip()
    if not cleaned:
        return "", False

    lower = cleaned.lower()
    disallowed_markers = [
        "let's tackle",
        "the user wants",
        "i need to",
        "first, i",
        "i should",
        "my response",
        "analysis:",
    ]

    if any(marker in lower for marker in disallowed_markers):
        extracted = extract_user_facing_text(cleaned)
        if extracted and len(extracted) >= 60 and extracted[-1] in ".!?":
            return extracted, False
        return fallback_plain_explanation(threat_type, risk_score, reasons, blocked), True

    # Keep only the first paragraph to avoid verbose or meta spill.
    first_paragraph = cleaned.split("\n\n")[0].strip()
    if len(first_paragraph) < 60:
        return fallback_plain_explanation(threat_type, risk_score, reasons, blocked), True
    if first_paragraph[-1] not in ".!?":
        return fallback_plain_explanation(threat_type, risk_score, reasons, blocked), True
    if len(first_paragraph) > 650:
        first_paragraph = first_paragraph[:650].rsplit(" ", 1)[0] + "..."
    return first_paragraph, False


async def llm_plain_explanation(
    threat_type: str,
    risk_score: int,
    reasons: List[str],
    blocked: bool = False,
    target: str = "this page",
) -> dict:
    if not OPENAI_API_KEY:
        return {
            "text": fallback_plain_explanation(threat_type, risk_score, reasons, blocked),
            "llm_used": False,
            "llm_error": "missing_api_key",
        }

    system_prompt = (
        "You are RelyX Guardian, a cybersecurity explainer for non-technical users. "
        "Primary objective: keep users safe with calm, clear, plain-language explanations. "
        "Rules: use everyday words, no jargon unless immediately explained, no fear-mongering, no blame. "
        "Output format: 3 short parts in one paragraph: (1) what happened, (2) why it is risky, (3) what RelyX did. "
        "Critical: never output your reasoning steps, planning notes, or phrases like 'the user wants' or 'I need to'. "
        "Only output the final user-facing explanation text. "
        "Always include a confidence phrase: low, medium, or high. "
        "Keep to 60-110 words."
    )

    user_prompt = (
        f"Target: {target}\n"
        f"Threat type: {threat_type}\n"
        f"Risk score: {risk_score}/100\n"
        f"Blocked: {blocked}\n"
        f"Reasons: {reasons[:3]}\n"
        "Write a user-facing explanation that any non-technical person can understand."
    )

    try:
        text = await asyncio.to_thread(_llm_chat_completion, system_prompt, user_prompt)
        clean_text, sanitized_to_fallback = sanitize_llm_output(text, threat_type, risk_score, reasons, blocked)

        # If first pass leaked meta reasoning, try one strict rewrite pass before fallback.
        if sanitized_to_fallback:
            retry_text = await asyncio.to_thread(_llm_rewrite_final, threat_type, risk_score, reasons, blocked, target)
            retry_clean_text, retry_sanitized = sanitize_llm_output(retry_text, threat_type, risk_score, reasons, blocked)
            if retry_clean_text and not retry_sanitized:
                return {
                    "text": retry_clean_text,
                    "llm_used": True,
                    "llm_error": None,
                }

        if clean_text:
            return {
                "text": clean_text,
                "llm_used": not sanitized_to_fallback,
                "llm_error": "llm_output_sanitized_to_fallback" if sanitized_to_fallback else None,
            }

        return {
            "text": fallback_plain_explanation(threat_type, risk_score, reasons, blocked),
            "llm_used": False,
            "llm_error": "empty_llm_response",
        }
    except Exception as exc:
        return {
            "text": fallback_plain_explanation(threat_type, risk_score, reasons, blocked),
            "llm_used": False,
            "llm_error": f"llm_call_failed: {str(exc)[:140]}",
        }


def classify_download(payload: DownloadRequest, trusted_domains: List[str]) -> dict:
    file_name = (payload.filename or "").lower()
    source_url = (payload.source_url or payload.final_url or "").lower()
    referrer = (payload.referrer or "").lower()
    mime = (payload.mime or "").lower()
    reasons = []
    risk_score = 0

    risky_ext = [".exe", ".msi", ".bat", ".cmd", ".scr", ".js", ".vbs", ".iso", ".apk", ".zip", ".rar"]
    matched_ext = next((ext for ext in risky_ext if file_name.endswith(ext)), None)
    source_domain = parse_domain(source_url)

    if matched_ext:
        risk_score += 60
        reasons.append(f"This file type ({matched_ext}) is often used to spread malware.")

    if source_url.startswith("http://"):
        risk_score += 20
        reasons.append("The download source is not secure (HTTP).")

    if any(term in source_url for term in ["free", "crack", "keygen", "patch"]):
        risk_score += 18
        reasons.append("The download URL includes terms commonly linked to unsafe files.")

    if any(term in referrer for term in ["urgent", "verify", "login"]):
        risk_score += 12
        reasons.append("The source page uses urgency or credential language.")

    if "application/x-msdownload" in mime or "application/x-dosexec" in mime:
        risk_score += 15
        reasons.append("File metadata suggests executable content.")

    if payload.total_bytes > 0 and payload.total_bytes < 5000:
        risk_score += 8
        reasons.append("Very small executable-like files can be suspicious.")

    if is_trusted_domain(source_domain, trusted_domains):
        risk_score = max(0, risk_score - 35)
        reasons.insert(0, "Source domain matches RelyX trusted list.")

    risk_score = min(100, risk_score)
    should_block = risk_score >= 60
    threat_type = "Risky Download" if risk_score >= 45 else "Likely Safe"

    return {
        "risk_score": risk_score,
        "threat_type": threat_type,
        "reasons": reasons[:3],
        "should_block": should_block,
        "source_domain": source_domain,
        "is_trusted_domain": is_trusted_domain(source_domain, trusted_domains),
    }


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "llm_enabled": bool(OPENAI_API_KEY),
        "model": OPENAI_MODEL,
        "base_url": OPENAI_BASE_URL,
        "key_source": OPENAI_API_KEY_SOURCE,
    }

@app.post("/analyze-url")
async def analyze_url(payload: URLRequest) -> dict:
    trusted_domains = payload.trusted_domains or DEFAULT_TRUSTED_DOMAINS
    url_result = classify_url(payload.url, trusted_domains)
    risk_score = url_result["url_score"]
    threat_type = "Likely Safe" if risk_score < 45 else "Phishing Suspicion"
    explanation = generate_explanation(payload.url, risk_score, threat_type, url_result["url_reasons"])
    llm_result = await llm_plain_explanation(
        threat_type=threat_type,
        risk_score=risk_score,
        reasons=url_result["url_reasons"],
        blocked=risk_score >= 68,
        target=payload.url,
    )

    return {
        "url": payload.url,
        "risk_score": risk_score,
        "threat_type": threat_type,
        "reasons": url_result["url_reasons"][:3],
        "explanation": llm_result["text"],
        "llm_used": llm_result["llm_used"],
        "llm_error": llm_result["llm_error"],
        "technical_explanation": explanation,
        "https": url_result["https"],
        "domain_age_days": url_result["domain_age_days"],
        "is_trusted_domain": url_result["is_trusted_domain"],
        "trusted_domains_used": trusted_domains,
    }


@app.post("/analyze-page")
async def analyze_page(payload: PageRequest) -> dict:
    trusted_domains = payload.trusted_domains or DEFAULT_TRUSTED_DOMAINS
    url_result = classify_url(payload.url, trusted_domains)
    content_result = classify_content(
        page_text=payload.page_text,
        keyword_hits=payload.keyword_hits,
        has_sensitive_inputs=payload.has_sensitive_inputs,
        suspicious_download_links=payload.suspicious_download_links,
    )

    total_score = min(100, int(url_result["url_score"] * 0.55 + content_result["content_score"] * 0.45))

    # Increase severity for unsafe credential forms on weak/tricky pages.
    if payload.has_sensitive_inputs and not url_result["https"]:
        total_score = min(100, total_score + 10)

    if url_result["is_trusted_domain"]:
        total_score = max(0, total_score - 20)

    threat_type = select_threat_type(
        total_score,
        has_sensitive_inputs=payload.has_sensitive_inputs,
        suspicious_download_links=payload.suspicious_download_links,
    )

    reasons = (url_result["url_reasons"] + content_result["content_reasons"])[:3]
    explanation = generate_explanation(payload.url, total_score, threat_type, reasons)
    llm_result = await llm_plain_explanation(
        threat_type=threat_type,
        risk_score=total_score,
        reasons=reasons,
        blocked=total_score >= 68,
        target=payload.url,
    )

    return {
        "url": payload.url,
        "risk_score": total_score,
        "threat_type": threat_type,
        "reasons": reasons,
        "explanation": llm_result["text"],
        "llm_used": llm_result["llm_used"],
        "llm_error": llm_result["llm_error"],
        "technical_explanation": explanation,
        "https": url_result["https"],
        "domain_age_days": url_result["domain_age_days"],
        "keyword_hits": payload.keyword_hits,
        "has_sensitive_inputs": payload.has_sensitive_inputs,
        "suspicious_download_links": payload.suspicious_download_links,
        "is_trusted_domain": url_result["is_trusted_domain"],
        "trusted_domains_used": trusted_domains,
    }


@app.post("/analyze-download")
async def analyze_download(payload: DownloadRequest) -> dict:
    trusted_domains = payload.trusted_domains or DEFAULT_TRUSTED_DOMAINS
    report = classify_download(payload, trusted_domains)
    llm_result = await llm_plain_explanation(
        threat_type=report["threat_type"],
        risk_score=report["risk_score"],
        reasons=report["reasons"],
        blocked=report["should_block"],
        target=payload.source_url,
    )
    report["explanation"] = llm_result["text"]
    report["llm_used"] = llm_result["llm_used"]
    report["llm_error"] = llm_result["llm_error"]
    report["trusted_domains_used"] = trusted_domains
    return report


@app.post("/explain")
async def explain(payload: ExplainRequest) -> dict:
    explanation = generate_explanation(
        payload.url or "",
        payload.risk_score,
        payload.threat_type,
        payload.reasons,
    )
    llm_result = await llm_plain_explanation(
        threat_type=payload.threat_type,
        risk_score=payload.risk_score,
        reasons=payload.reasons,
        blocked=payload.risk_score >= 68,
        target=payload.url or "this page",
    )

    return {
        "risk_score": payload.risk_score,
        "threat_type": payload.threat_type,
        "key_reasons": payload.reasons[:3],
        "explanation": llm_result["text"],
        "llm_used": llm_result["llm_used"],
        "llm_error": llm_result["llm_error"],
        "technical_explanation": explanation,
    }
