# pyright: reportMissingImports=false
import asyncio
import base64
import logging
import json
import math
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from difflib import SequenceMatcher
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None


APP_VERSION = "1.0.0"
BLOCK_THRESHOLD = 70
API_TIMEOUT_SECONDS = 8.0
CACHE_TTL_SECONDS = 300

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

SUSPICIOUS_TLDS = {
    "zip",
    "top",
    "xyz",
    "click",
    "link",
    "gq",
    "cf",
    "tk",
    "work",
    "rest",
    "cam",
}

RISKY_DOWNLOAD_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".vbs",
    ".iso",
    ".apk",
    ".zip",
    ".rar",
}

URL_LURE_TERMS = [
    "secure",
    "verify",
    "signin",
    "login",
    "account",
    "wallet",
    "invoice",
    "payment",
    "bonus",
    "gift",
    "free",
    "update",
]


def load_dotenv_flexible() -> None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Supports both KEY=VALUE and PowerShell style $env:KEY="VALUE".
        if line.startswith("$env:"):
            line = line[5:]
            if "=" not in line:
                continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"").strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_dotenv_flexible()

OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://integrate.api.nvidia.com/v1").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "sarvamai/sarvam-m").strip()
NVIDIA_API_KEY = "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"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "").strip()
WHOIS_API_URL = os.getenv(
    "WHOIS_API_URL",
    "https://www.whoisxmlapi.com/whoisserver/WhoisService",
).strip()
PHISHTANK_CHECK_URL = os.getenv(
    "PHISHTANK_CHECK_URL",
    "https://checkurl.phishtank.com/checkurl/",
).strip()


LLM_PROVIDER = "nvidia"
LLM_API_KEY = NVIDIA_API_KEY
LLM_LOGGER = logging.getLogger("relyx.ai")
if not LLM_LOGGER.handlers:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

app = FastAPI(title="RelyX Active Security API", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str
    trusted_domains: list[str] = Field(default_factory=list)


class PageRequest(BaseModel):
    url: str
    page_text: str = ""
    matched_keywords: list[str] = Field(default_factory=list)
    keyword_hits: int = 0
    has_sensitive_inputs: bool = False
    hidden_sensitive_inputs: int = 0
    external_form_actions: int = 0
    suspicious_download_links: int = 0
    urgency_hits: int = 0
    fear_hits: int = 0
    credential_harvest_hits: int = 0
    highlight_selectors: list[str] = Field(default_factory=list)
    trusted_domains: list[str] = Field(default_factory=list)


class DownloadRequest(BaseModel):
    filename: str = ""
    source_url: str = ""
    referrer: str = ""
    mime: str = ""
    total_bytes: int = 0
    final_url: str = ""
    trusted_domains: list[str] = Field(default_factory=list)


class ExplainRequest(BaseModel):
    url: Optional[str] = None
    risk_score: int
    threat_type: str
    severity: str
    reasons: list[str] = Field(default_factory=list)


class Signal:
    def __init__(self, signal: str, impact: int, detail: str, category: str) -> None:
        self.signal = signal
        self.impact = impact
        self.detail = detail
        self.category = category

    def as_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "impact": self.impact,
            "detail": self.detail,
            "category": self.category,
        }


def clamp_score(score: int) -> int:
    return max(0, min(100, int(round(score))))


def parse_domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().strip()
    except Exception:
        return ""


def is_http_url(url: str) -> bool:
    if not isinstance(url, str):
        return False
    return url.startswith("http://") or url.startswith("https://")


def root_domain(host: str) -> str:
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def host_label(host: str) -> str:
    return root_domain(host).split(".")[0]


def is_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))


def calculate_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def is_trusted_domain(host: str, trusted_domains: list[str]) -> bool:
    host = (host or "").lower().strip()
    if not host:
        return False
    for trusted in trusted_domains:
        trusted = trusted.lower().strip()
        if not trusted:
            continue
        if host == trusted or host.endswith(f".{trusted}"):
            return True
    return False


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def threat_type_from_signals(score: int, has_sensitive_inputs: bool, risky_downloads: int, api_flags: dict[str, Any]) -> str:
    if risky_downloads > 0 and score >= 60:
        return "Malware or Risky Download"
    if api_flags.get("phishtank") or api_flags.get("google_safe_browsing"):
        return "Known Phishing Threat"
    if has_sensitive_inputs and score >= 55:
        return "Credential Theft Risk"
    if score >= 45:
        return "Suspicious Website"
    return "Likely Safe"


def confidence_from_telemetry(api_checks: dict[str, dict[str, Any]]) -> str:
    queried = 0
    failed = 0
    for result in api_checks.values():
        if result.get("queried"):
            queried += 1
        if result.get("error"):
            failed += 1

    if queried >= 3 and failed == 0:
        return "high"
    if queried >= 1:
        return "medium"
    return "low"


def build_url_pattern_signals(url: str, domain: str, trusted_domains: list[str]) -> tuple[list[Signal], dict[str, Any]]:
    lower_url = (url or "").lower()
    signals: list[Signal] = []
    host = (domain or "").lower()
    tld = host.split(".")[-1] if "." in host else ""
    subdomain_depth = max(0, len(host.split(".")) - 2) if host else 0

    if lower_url.startswith("http://"):
        signals.append(
            Signal(
                "http_transport",
                18,
                "Connection is not encrypted with HTTPS.",
                "transport",
            )
        )

    if "@" in lower_url:
        signals.append(
            Signal(
                "url_at_symbol",
                16,
                "URL includes '@', a common obfuscation trick.",
                "url",
            )
        )

    if "xn--" in host:
        signals.append(
            Signal(
                "punycode_domain",
                20,
                "Punycode domain detected (possible homograph attack).",
                "url",
            )
        )

    if is_ip_host(host):
        signals.append(
            Signal(
                "ip_host",
                24,
                "IP address used instead of normal domain name.",
                "url",
            )
        )

    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        signals.append(
            Signal(
                "hyphenated_domain",
                min(18, hyphen_count * 3),
                f"Domain has {hyphen_count} hyphens.",
                "url",
            )
        )

    if subdomain_depth >= 3:
        signals.append(
            Signal(
                "deep_subdomain",
                min(16, subdomain_depth * 4),
                f"Domain has deep subdomain nesting ({subdomain_depth}).",
                "url",
            )
        )

    if len(lower_url) >= 140:
        signals.append(
            Signal(
                "long_url",
                10,
                "Unusually long URL often used for masking destination.",
                "url",
            )
        )

    lure_hits = [term for term in URL_LURE_TERMS if term in lower_url]
    if lure_hits:
        signals.append(
            Signal(
                "lure_terms",
                min(16, 6 + len(lure_hits) * 2),
                f"Suspicious lure terms in URL: {', '.join(lure_hits[:4])}.",
                "url",
            )
        )

    if tld in SUSPICIOUS_TLDS:
        signals.append(
            Signal(
                "risky_tld",
                14,
                f"Top-level domain '.{tld}' is frequently abused.",
                "url",
            )
        )

    label = host_label(host)
    for trusted in trusted_domains:
        trusted_label = host_label(trusted)
        if not trusted_label or trusted_label == label:
            continue
        similarity = SequenceMatcher(a=label, b=trusted_label).ratio()
        if similarity >= 0.88 and abs(len(label) - len(trusted_label)) <= 3:
            signals.append(
                Signal(
                    "typosquatting_pattern",
                    22,
                    f"Domain '{label}' looks similar to trusted '{trusted_label}'.",
                    "url",
                )
            )
            break

    trusted = is_trusted_domain(host, trusted_domains)
    if trusted:
        signals.append(
            Signal(
                "trusted_domain",
                -35,
                "Trusted domain matched allowlist.",
                "trust",
            )
        )

    url_features = {
        "length": len(lower_url),
        "entropy": calculate_entropy(lower_url),
        "tld": tld,
        "subdomain_depth": subdomain_depth,
        "has_punycode": "xn--" in host,
        "has_ip_host": is_ip_host(host),
        "has_at_symbol": "@" in lower_url,
        "hyphen_count": hyphen_count,
        "trusted_domain": trusted,
    }

    return signals, url_features


def parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except Exception:
            pass
        try:
            return parsedate_to_datetime(text)
        except Exception:
            return None
    return None


async def get_domain_age_days(domain: str) -> tuple[Optional[int], dict[str, Any]]:
    telemetry = {"queried": False, "source": "none", "error": None}
    if not domain or is_ip_host(domain) or domain.endswith(".local"):
        return None, telemetry

    # WHOIS API path.
    if WHOIS_API_KEY:
        try:
            telemetry["queried"] = True
            telemetry["source"] = "whois_api"
            params = {
                "apiKey": WHOIS_API_KEY,
                "domainName": domain,
                "outputFormat": "JSON",
            }
            async with httpx.AsyncClient(timeout=API_TIMEOUT_SECONDS) as client:
                response = await client.get(WHOIS_API_URL, params=params)
                response.raise_for_status()
                payload = response.json()

            record = payload.get("WhoisRecord", {}) if isinstance(payload, dict) else {}
            created_raw = (
                record.get("createdDateNormalized")
                or record.get("createdDate")
                or record.get("registryData", {}).get("createdDate")
            )
            created = parse_datetime(created_raw)
            if created is None:
                return None, telemetry
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            days = max(0, (datetime.now(timezone.utc) - created).days)
            return days, telemetry
        except Exception as exc:
            telemetry["error"] = f"whois_api_failed: {str(exc)[:120]}"

    # Local python-whois fallback.
    try:
        import whois

        telemetry["queried"] = True
        telemetry["source"] = "python_whois"
        result = await asyncio.to_thread(whois.whois, domain)
        created = result.creation_date if result is not None else None
        if isinstance(created, list) and created:
            created = created[0]
        created_dt = parse_datetime(created)
        if created_dt is None:
            return None, telemetry
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - created_dt).days), telemetry
    except Exception as exc:
        telemetry["error"] = f"python_whois_failed: {str(exc)[:120]}"
        return None, telemetry


def certificate_probe(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "queried": False,
        "valid": None,
        "days_left": None,
        "issuer": None,
        "error": None,
    }
    if not domain or is_ip_host(domain):
        return result

    try:
        result["queried"] = True
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()

        not_after = cert.get("notAfter")
        issuer = cert.get("issuer", [])
        issuer_name = ""
        if issuer:
            flattened = []
            for tuple_item in issuer:
                for key, value in tuple_item:
                    flattened.append(f"{key}={value}")
            issuer_name = ", ".join(flattened)

        expires = parse_datetime(not_after)
        if expires is not None:
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            result["days_left"] = days_left
            result["valid"] = days_left >= 0
        else:
            result["valid"] = None

        result["issuer"] = issuer_name or "Unknown"
        return result
    except Exception as exc:
        result["error"] = f"cert_probe_failed: {str(exc)[:120]}"
        return result


async def check_google_safe_browsing(url: str) -> dict[str, Any]:
    """Google Safe Browsing disabled - using PhishTank and VirusTotal instead."""
    return {
        "queried": False,
        "matched": False,
        "threats": [],
        "error": "disabled",
    }


async def check_virustotal_url(url: str) -> dict[str, Any]:
    result = {
        "queried": False,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "error": None,
    }
    if not VIRUSTOTAL_API_KEY:
        result["error"] = "missing_virustotal_key"
        return result

    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded}"

    try:
        result["queried"] = True
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        async with httpx.AsyncClient(timeout=API_TIMEOUT_SECONDS) as client:
            response = await client.get(endpoint, headers=headers)
            response.raise_for_status()
            payload = response.json()

        stats = (
            payload.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        result["malicious"] = int(stats.get("malicious", 0) or 0)
        result["suspicious"] = int(stats.get("suspicious", 0) or 0)
        result["harmless"] = int(stats.get("harmless", 0) or 0)
        result["undetected"] = int(stats.get("undetected", 0) or 0)
        return result
    except Exception as exc:
        result["error"] = f"virustotal_failed: {str(exc)[:120]}"
        return result


async def check_phishtank(url: str) -> dict[str, Any]:
    result = {
        "queried": False,
        "matched": False,
        "verified": False,
        "in_database": False,
        "error": None,
    }

    payload = {
        "url": url,
        "format": "json",
    }
    # app_key is optional - without it, rate limits apply but API is free
    if PHISHTANK_API_KEY:
        payload["app_key"] = PHISHTANK_API_KEY

    try:
        result["queried"] = True
        headers = {
            "User-Agent": "RelyX-Active-Security/1.0",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        async with httpx.AsyncClient(timeout=API_TIMEOUT_SECONDS) as client:
            response = await client.post(PHISHTANK_CHECK_URL, data=payload, headers=headers)
            response.raise_for_status()
            body = response.text.strip()
            data = json.loads(body)

        results = data.get("results", {}) if isinstance(data, dict) else {}
        in_database = bool(results.get("in_database"))
        verified = bool(results.get("verified"))
        valid = bool(results.get("valid"))

        result["in_database"] = in_database
        result["verified"] = verified
        result["matched"] = in_database and (verified or valid)
        return result
    except Exception as exc:
        result["error"] = f"phishtank_failed: {str(exc)[:120]}"
        return result


def build_api_signals(
    domain: str,
    is_https: bool,
    cert: dict[str, Any],
    domain_age_days: Optional[int],
    gsb: dict[str, Any],
    vt: dict[str, Any],
    phishtank: dict[str, Any],
) -> tuple[list[Signal], dict[str, Any], dict[str, dict[str, Any]]]:
    signals: list[Signal] = []

    if not is_https:
        signals.append(
            Signal(
                "missing_https",
                18,
                "Site does not use HTTPS encryption.",
                "transport",
            )
        )

    if cert.get("queried"):
        if cert.get("valid") is False:
            signals.append(
                Signal(
                    "invalid_or_expired_certificate",
                    22,
                    "TLS certificate is invalid or expired.",
                    "certificate",
                )
            )
        elif isinstance(cert.get("days_left"), int) and cert["days_left"] < 15:
            signals.append(
                Signal(
                    "certificate_expiring_soon",
                    8,
                    f"Certificate expires in {cert['days_left']} days.",
                    "certificate",
                )
            )
    elif cert.get("error") and is_https:
        signals.append(
            Signal(
                "certificate_validation_failed",
                8,
                "Certificate validation could not be completed.",
                "certificate",
            )
        )

    if domain_age_days is not None:
        if domain_age_days < 30:
            signals.append(
                Signal(
                    "new_domain",
                    24,
                    f"Domain age is only {domain_age_days} days.",
                    "whois",
                )
            )
        elif domain_age_days < 180:
            signals.append(
                Signal(
                    "young_domain",
                    12,
                    f"Domain age is {domain_age_days} days.",
                    "whois",
                )
            )
    else:
        signals.append(
            Signal(
                "domain_age_unknown",
                6,
                "WHOIS domain age could not be verified.",
                "whois",
            )
        )

    if gsb.get("matched"):
        threats = gsb.get("threats") or ["unknown threat"]
        signals.append(
            Signal(
                "google_safe_browsing_match",
                70,
                f"Google Safe Browsing flagged threat types: {', '.join(threats[:3])}.",
                "threat_intel",
            )
        )

    vt_malicious = int(vt.get("malicious", 0) or 0)
    vt_suspicious = int(vt.get("suspicious", 0) or 0)
    if vt_malicious > 0:
        impact = min(70, 30 + vt_malicious * 5)
        signals.append(
            Signal(
                "virustotal_malicious",
                impact,
                f"VirusTotal reports {vt_malicious} malicious vendor detections.",
                "threat_intel",
            )
        )
    elif vt_suspicious > 0:
        impact = min(30, 10 + vt_suspicious * 4)
        signals.append(
            Signal(
                "virustotal_suspicious",
                impact,
                f"VirusTotal reports {vt_suspicious} suspicious detections.",
                "threat_intel",
            )
        )

    if phishtank.get("matched"):
        signals.append(
            Signal(
                "phishtank_match",
                65,
                "PhishTank reports this URL as phishing.",
                "threat_intel",
            )
        )

    api_flags = {
        "google_safe_browsing": bool(gsb.get("matched")),
        "virustotal_malicious": vt_malicious > 0,
        "virustotal_suspicious": vt_suspicious > 0,
        "phishtank": bool(phishtank.get("matched")),
    }

    api_checks = {
        "google_safe_browsing": gsb,
        "virustotal": vt,
        "phishtank": phishtank,
        "certificate": cert,
    }

    return signals, api_flags, api_checks


def build_page_signals(payload: PageRequest) -> list[Signal]:
    signals: list[Signal] = []

    if payload.keyword_hits > 0:
        impact = min(24, payload.keyword_hits * 2)
        signals.append(
            Signal(
                "keyword_pressure_language",
                impact,
                f"Detected {payload.keyword_hits} suspicious keyword hits in page content.",
                "content",
            )
        )

    if payload.has_sensitive_inputs:
        signals.append(
            Signal(
                "sensitive_form_fields",
                14,
                "Email or password inputs detected on the page.",
                "dom",
            )
        )

    if payload.hidden_sensitive_inputs > 0:
        signals.append(
            Signal(
                "hidden_sensitive_fields",
                min(30, payload.hidden_sensitive_inputs * 10),
                f"Hidden sensitive inputs found: {payload.hidden_sensitive_inputs}.",
                "dom",
            )
        )

    if payload.external_form_actions > 0:
        signals.append(
            Signal(
                "external_form_submission",
                min(30, payload.external_form_actions * 10),
                f"Form submits to external domain: {payload.external_form_actions} form(s).",
                "dom",
            )
        )

    if payload.suspicious_download_links > 0:
        signals.append(
            Signal(
                "suspicious_download_links",
                min(32, payload.suspicious_download_links * 12),
                f"Suspicious downloadable links detected: {payload.suspicious_download_links}.",
                "dom",
            )
        )

    nlp_impact = min(
        35,
        payload.urgency_hits * 4
        + payload.fear_hits * 5
        + payload.credential_harvest_hits * 8,
    )
    if nlp_impact > 0:
        signals.append(
            Signal(
                "social_engineering_language",
                nlp_impact,
                (
                    f"NLP cues -> urgency:{payload.urgency_hits}, "
                    f"fear:{payload.fear_hits}, credential:{payload.credential_harvest_hits}."
                ),
                "nlp",
            )
        )

    return signals


def build_download_signals(payload: DownloadRequest) -> list[Signal]:
    signals: list[Signal] = []
    filename = (payload.filename or "").lower()
    source_url = (payload.source_url or payload.final_url or "").lower()
    referrer = (payload.referrer or "").lower()
    mime = (payload.mime or "").lower()

    matched_ext = next((ext for ext in RISKY_DOWNLOAD_EXTENSIONS if filename.endswith(ext)), None)
    if matched_ext:
        signals.append(
            Signal(
                "risky_file_extension",
                55,
                f"Downloaded file extension '{matched_ext}' is frequently abused.",
                "download",
            )
        )

    if source_url.startswith("http://"):
        signals.append(
            Signal(
                "download_over_http",
                18,
                "Download source is not encrypted (HTTP).",
                "download",
            )
        )

    if any(term in source_url for term in ["crack", "keygen", "patch", "free-download"]):
        signals.append(
            Signal(
                "download_lure_terms",
                14,
                "Download URL includes terms frequently tied to malware distribution.",
                "download",
            )
        )

    if any(term in referrer for term in ["verify", "urgent", "account", "security"]):
        signals.append(
            Signal(
                "suspicious_referrer_language",
                10,
                "Referrer contains urgency or credential-theft style language.",
                "download",
            )
        )

    if "application/x-msdownload" in mime or "application/x-dosexec" in mime:
        signals.append(
            Signal(
                "executable_mime",
                16,
                "File MIME type indicates executable content.",
                "download",
            )
        )

    if payload.total_bytes > 0 and payload.total_bytes < 6000:
        signals.append(
            Signal(
                "tiny_executable_like_file",
                8,
                "Tiny executable-like files can indicate droppers.",
                "download",
            )
        )

    return signals


def finalize_reason_list(signals: list[Signal], max_items: int = 3) -> list[str]:
    ranked = sorted(signals, key=lambda s: abs(s.impact), reverse=True)
    return [signal.detail for signal in ranked[:max_items]]


def parse_llm_json_content(content: str) -> dict[str, Any]:
    text = (content or "").strip()
    if not text:
        raise ValueError("empty_llm_output")

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE | re.DOTALL).strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        parsed = json.loads(text[start : end + 1])
        if isinstance(parsed, dict):
            return parsed

    raise ValueError("invalid_llm_json")


def log_llm_status(message: str, **details: Any) -> None:
    payload = ", ".join(f"{key}={value}" for key, value in details.items() if value is not None)
    if payload:
        LLM_LOGGER.info("%s | %s", message, payload)
    else:
        LLM_LOGGER.info("%s", message)


def stream_nvidia_explanation(client: Any, system_prompt: str, user_payload: dict[str, Any]) -> str:
    stream = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload)},
        ],
        temperature=0.5,
        top_p=1,
        max_tokens=16384,
        stream=True,
    )

    chunks: list[str] = []
    for chunk in stream:
        try:
            delta = chunk.choices[0].delta.content
        except Exception:
            delta = None
        if delta is not None:
            chunks.append(delta)
    return "".join(chunks).strip()


async def explain_with_llm(
    risk_score: int,
    severity: str,
    threat_type: str,
    reasons: list[str],
    api_flags: dict[str, Any],
    confidence: str,
) -> dict[str, Any]:
    log_llm_status(
        "LLM request started",
        provider=LLM_PROVIDER,
        base_url=OPENAI_BASE_URL,
        model=OPENAI_MODEL,
        has_key=bool(LLM_API_KEY),
    )

    fallback = {
        "threat_type": threat_type,
        "severity": severity,
        "reasons": reasons[:3],
        "summary": (
            f"RelyX assigned risk {risk_score}/100 ({severity}) based on verified signals. "
            f"Top reasons: {' '.join(reasons[:3])}"
        ).strip(),
        "llm_used": False,
        "llm_error": "missing_nvidia_key",
        "llm_provider": LLM_PROVIDER,
        "llm_model": OPENAI_MODEL,
    }

    if not LLM_API_KEY:
        log_llm_status("LLM request aborted", reason="missing NVIDIA API key")
        return fallback

    if OpenAI is None:
        log_llm_status("LLM request aborted", reason="openai client unavailable")
        return fallback

    try:
        client = OpenAI(base_url=OPENAI_BASE_URL, api_key=LLM_API_KEY)
        system_prompt = (
            "You are a deterministic security explanation engine. "
            "Never change the provided risk score, threat type, or severity. "
            "Respond with JSON only using this exact schema: "
            "{\"threat_type\":string,\"severity\":string,\"reasons\":string[2-3],\"summary\":string}."
        )
        user_payload = {
            "risk_score": risk_score,
            "threat_type": threat_type,
            "severity": severity,
            "confidence": confidence,
            "api_flags": api_flags,
            "detected_reasons": reasons[:5],
            "constraints": {
                "reason_count": "2-3",
                "tone": "clear, concise, trust-building",
            },
        }

        content = await asyncio.to_thread(
            stream_nvidia_explanation,
            client,
            system_prompt,
            user_payload,
        )

        log_llm_status("LLM stream completed", content_length=len(content))
        if not content:
            fallback["llm_error"] = "empty_llm_output"
            log_llm_status("LLM request returned empty output")
            return fallback

        parsed = parse_llm_json_content(content)
        parsed_reasons = parsed.get("reasons", []) if isinstance(parsed, dict) else []
        if not isinstance(parsed_reasons, list):
            parsed_reasons = reasons[:3]

        clean_reasons = [str(reason).strip() for reason in parsed_reasons if str(reason).strip()][:3]
        if len(clean_reasons) < 2:
            clean_reasons = reasons[:3]

        summary = str(parsed.get("summary", "")).strip() if isinstance(parsed, dict) else ""
        if not summary:
            summary = fallback["summary"]

        return {
            "threat_type": threat_type,
            "severity": severity,
            "reasons": clean_reasons,
            "summary": summary,
            "llm_used": True,
            "llm_error": None,
            "llm_provider": LLM_PROVIDER,
            "llm_model": OPENAI_MODEL,
        }
    except Exception as exc:
        fallback["llm_error"] = f"llm_failed: {str(exc)[:120]}"
        log_llm_status("LLM request failed", error=fallback["llm_error"])
        return fallback


async def analyze_url_core(url: str, trusted_domains: list[str]) -> dict[str, Any]:
    domain = parse_domain(url)
    trusted = trusted_domains or DEFAULT_TRUSTED_DOMAINS

    pattern_signals, url_features = build_url_pattern_signals(url, domain, trusted)

    gsb_task = check_google_safe_browsing(url)
    vt_task = check_virustotal_url(url)
    phish_task = check_phishtank(url)
    age_task = get_domain_age_days(domain)
    cert_task = asyncio.to_thread(certificate_probe, domain)

    gsb, vt, phishtank, age_result, cert = await asyncio.gather(
        gsb_task,
        vt_task,
        phish_task,
        age_task,
        cert_task,
    )

    domain_age_days, whois_telemetry = age_result
    api_signals, api_flags, api_checks = build_api_signals(
        domain=domain,
        is_https=url.lower().startswith("https://"),
        cert=cert,
        domain_age_days=domain_age_days,
        gsb=gsb,
        vt=vt,
        phishtank=phishtank,
    )
    api_checks["whois"] = whois_telemetry

    all_signals = pattern_signals + api_signals
    risk_score = clamp_score(sum(signal.impact for signal in all_signals))
    confidence = confidence_from_telemetry(api_checks)
    severity = severity_from_score(risk_score)
    threat_type = threat_type_from_signals(
        score=risk_score,
        has_sensitive_inputs=False,
        risky_downloads=0,
        api_flags=api_flags,
    )

    reasons = finalize_reason_list(all_signals)
    explanation_result = await explain_with_llm(
        risk_score=risk_score,
        severity=severity,
        threat_type=threat_type,
        reasons=reasons,
        api_flags=api_flags,
        confidence=confidence,
    )

    return {
        "url": url,
        "risk_score": risk_score,
        "block_threshold": BLOCK_THRESHOLD,
        "should_block": risk_score >= BLOCK_THRESHOLD,
        "threat_type": explanation_result["threat_type"],
        "severity": explanation_result["severity"],
        "confidence_level": confidence,
        "reasons": explanation_result["reasons"],
        "explanation": explanation_result["summary"],
        "llm_used": explanation_result["llm_used"],
        "llm_error": explanation_result["llm_error"],
        "llm_provider": explanation_result.get("llm_provider", LLM_PROVIDER),
        "llm_model": explanation_result.get("llm_model", OPENAI_MODEL),
        "https": url.lower().startswith("https://"),
        "domain": domain,
        "domain_age_days": domain_age_days,
        "is_trusted_domain": is_trusted_domain(domain, trusted),
        "api_flags": api_flags,
        "api_checks": api_checks,
        "xai": {
            "model": "deterministic_multilayer_v1",
            "feature_contributions": [s.as_dict() for s in sorted(all_signals, key=lambda s: abs(s.impact), reverse=True)[:10]],
            "url_features": url_features,
            "threat_intel": {
                "google_safe_browsing": gsb,
                "virustotal": vt,
                "phishtank": phishtank,
                "whois": whois_telemetry,
                "certificate": cert,
            },
        },
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "version": APP_VERSION,
        "llm_enabled": bool(LLM_API_KEY),
        "llm_provider": LLM_PROVIDER,
        "llm_model": OPENAI_MODEL,
        "google_safe_browsing_enabled": False,
        "virustotal_enabled": bool(VIRUSTOTAL_API_KEY),
        "phishtank_enabled": True,
        "whois_api_enabled": bool(WHOIS_API_KEY),
    }


@app.post("/analyze-url")
async def analyze_url(payload: URLRequest) -> dict[str, Any]:
    if not is_http_url(payload.url):
        return {
            "url": payload.url,
            "risk_score": 0,
            "block_threshold": BLOCK_THRESHOLD,
            "should_block": False,
            "threat_type": "Likely Safe",
            "severity": "low",
            "confidence_level": "low",
            "reasons": ["Only HTTP/HTTPS URLs are analyzed."],
            "explanation": "RelyX only analyzes web URLs.",
            "llm_used": False,
            "llm_error": "unsupported_scheme",
            "llm_provider": LLM_PROVIDER,
            "llm_model": OPENAI_MODEL,
            "https": False,
            "domain": "",
            "domain_age_days": None,
            "is_trusted_domain": False,
            "api_flags": {},
            "api_checks": {},
            "xai": {
                "model": "deterministic_multilayer_v1",
                "feature_contributions": [],
                "url_features": {},
                "threat_intel": {},
            },
        }

    trusted = payload.trusted_domains or DEFAULT_TRUSTED_DOMAINS
    return await analyze_url_core(payload.url, trusted)


@app.post("/analyze-page")
async def analyze_page(payload: PageRequest) -> dict[str, Any]:
    trusted = payload.trusted_domains or DEFAULT_TRUSTED_DOMAINS
    base = await analyze_url_core(payload.url, trusted)

    page_signals = build_page_signals(payload)
    all_signals = [
        Signal(signal["signal"], int(signal["impact"]), signal["detail"], signal["category"])
        for signal in base["xai"]["feature_contributions"]
    ] + page_signals

    score = clamp_score(sum(signal.impact for signal in all_signals))
    if payload.has_sensitive_inputs and score >= 55:
        score = clamp_score(score + 8)

    severity = severity_from_score(score)
    threat_type = threat_type_from_signals(
        score=score,
        has_sensitive_inputs=payload.has_sensitive_inputs,
        risky_downloads=payload.suspicious_download_links,
        api_flags=base.get("api_flags", {}),
    )

    reasons = finalize_reason_list(all_signals)
    confidence = base.get("confidence_level", "low")
    if confidence == "low" and (payload.keyword_hits > 0 or payload.has_sensitive_inputs):
        confidence = "low"

    explanation_result = await explain_with_llm(
        risk_score=score,
        severity=severity,
        threat_type=threat_type,
        reasons=reasons,
        api_flags=base.get("api_flags", {}),
        confidence=confidence,
    )

    base["risk_score"] = score
    base["should_block"] = score >= BLOCK_THRESHOLD
    base["threat_type"] = explanation_result["threat_type"]
    base["severity"] = explanation_result["severity"]
    base["reasons"] = explanation_result["reasons"]
    base["explanation"] = explanation_result["summary"]
    base["llm_used"] = explanation_result["llm_used"]
    base["llm_error"] = explanation_result["llm_error"]
    base["llm_provider"] = explanation_result.get("llm_provider", LLM_PROVIDER)
    base["llm_model"] = explanation_result.get("llm_model", OPENAI_MODEL)
    base["confidence_level"] = confidence
    base["keyword_hits"] = payload.keyword_hits
    base["has_sensitive_inputs"] = payload.has_sensitive_inputs
    base["hidden_sensitive_inputs"] = payload.hidden_sensitive_inputs
    base["external_form_actions"] = payload.external_form_actions
    base["suspicious_download_links"] = payload.suspicious_download_links
    base["urgency_hits"] = payload.urgency_hits
    base["fear_hits"] = payload.fear_hits
    base["credential_harvest_hits"] = payload.credential_harvest_hits

    base["xai"]["feature_contributions"] = [
        signal.as_dict()
        for signal in sorted(all_signals, key=lambda item: abs(item.impact), reverse=True)[:12]
    ]
    base["xai"]["dom"] = {
        "highlight_selectors": payload.highlight_selectors[:10],
        "has_sensitive_inputs": payload.has_sensitive_inputs,
        "hidden_sensitive_inputs": payload.hidden_sensitive_inputs,
        "external_form_actions": payload.external_form_actions,
    }
    base["xai"]["nlp"] = {
        "urgency_hits": payload.urgency_hits,
        "fear_hits": payload.fear_hits,
        "credential_harvest_hits": payload.credential_harvest_hits,
    }

    return base


@app.post("/analyze-download")
async def analyze_download(payload: DownloadRequest) -> dict[str, Any]:
    source_url = payload.source_url or payload.final_url
    trusted = payload.trusted_domains or DEFAULT_TRUSTED_DOMAINS

    base = None
    if is_http_url(source_url):
        base = await analyze_url_core(source_url, trusted)
    else:
        base = {
            "risk_score": 0,
            "api_flags": {},
            "api_checks": {},
            "xai": {
                "feature_contributions": [],
                "threat_intel": {},
                "url_features": {},
            },
            "confidence_level": "low",
            "is_trusted_domain": False,
            "domain": "",
            "https": False,
        }

    download_signals = build_download_signals(payload)
    base_signals = [
        Signal(signal["signal"], int(signal["impact"]), signal["detail"], signal["category"])
        for signal in base["xai"]["feature_contributions"]
    ]

    all_signals = base_signals + download_signals
    score = clamp_score(sum(signal.impact for signal in all_signals))
    severity = severity_from_score(score)

    threat_type = threat_type_from_signals(
        score=score,
        has_sensitive_inputs=False,
        risky_downloads=1 if payload.filename else 0,
        api_flags=base.get("api_flags", {}),
    )
    reasons = finalize_reason_list(all_signals)

    confidence = base.get("confidence_level", "low")
    if not base.get("api_checks"):
        confidence = "low"

    explanation_result = await explain_with_llm(
        risk_score=score,
        severity=severity,
        threat_type=threat_type,
        reasons=reasons,
        api_flags=base.get("api_flags", {}),
        confidence=confidence,
    )

    return {
        "risk_score": score,
        "block_threshold": BLOCK_THRESHOLD,
        "should_block": score >= 60,
        "threat_type": explanation_result["threat_type"],
        "severity": explanation_result["severity"],
        "confidence_level": confidence,
        "reasons": explanation_result["reasons"],
        "explanation": explanation_result["summary"],
        "llm_used": explanation_result["llm_used"],
        "llm_error": explanation_result["llm_error"],
        "llm_provider": explanation_result.get("llm_provider", LLM_PROVIDER),
        "llm_model": explanation_result.get("llm_model", OPENAI_MODEL),
        "source_url": source_url,
        "filename": payload.filename,
        "is_trusted_domain": bool(base.get("is_trusted_domain")),
        "api_flags": base.get("api_flags", {}),
        "api_checks": base.get("api_checks", {}),
        "xai": {
            "model": "deterministic_multilayer_v1",
            "feature_contributions": [
                signal.as_dict()
                for signal in sorted(all_signals, key=lambda item: abs(item.impact), reverse=True)[:12]
            ],
            "threat_intel": base.get("xai", {}).get("threat_intel", {}),
            "url_features": base.get("xai", {}).get("url_features", {}),
        },
    }


@app.post("/explain")
async def explain(payload: ExplainRequest) -> dict[str, Any]:
    reasons = payload.reasons[:3] if payload.reasons else ["Risk signals were detected."]
    result = await explain_with_llm(
        risk_score=payload.risk_score,
        severity=payload.severity,
        threat_type=payload.threat_type,
        reasons=reasons,
        api_flags={},
        confidence="low",
    )
    return {
        "risk_score": payload.risk_score,
        "threat_type": result["threat_type"],
        "severity": result["severity"],
        "reasons": result["reasons"],
        "explanation": result["summary"],
        "llm_used": result["llm_used"],
        "llm_error": result["llm_error"],
        "llm_provider": result.get("llm_provider", LLM_PROVIDER),
        "llm_model": result.get("llm_model", OPENAI_MODEL),
    }
