import asyncio
import base64
import os
import time
from email import message_from_string
from typing import Any

import dns.resolver
import httpx
import whois

RATE_BUCKET: dict[str, float] = {}
SECRET_SERVICE_URL = os.getenv("SECRET_SERVICE_URL", "http://secret-service:8001")
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")


async def _throttle(api: str, per_seconds: float = 1.0) -> None:
    now = time.monotonic()
    last = RATE_BUCKET.get(api, 0.0)
    wait = per_seconds - (now - last)
    if wait > 0:
        await asyncio.sleep(wait)
    RATE_BUCKET[api] = time.monotonic()


async def _vault_secret(secret_key: str) -> str | None:
    vault_addr = os.getenv("VAULT_ADDR", "")
    vault_token = os.getenv("VAULT_TOKEN", "")
    vault_path = os.getenv("VAULT_SECRET_PATH", "secret/data/sirp")
    if not vault_addr or not vault_token:
        return None

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{vault_addr}/v1/{vault_path}", headers={"X-Vault-Token": vault_token}
        )
        if resp.status_code != 200:
            return None
        payload = resp.json()
        return payload.get("data", {}).get("data", {}).get(secret_key)


async def _secret(name: str) -> str:
    headers = {"x-internal-token": INTERNAL_SERVICE_TOKEN} if INTERNAL_SERVICE_TOKEN else {}
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(f"{SECRET_SERVICE_URL}/secrets/{name}", headers=headers)
            if resp.status_code == 200:
                value = str(resp.json().get("value", ""))
                if value:
                    return value
    except Exception:
        pass

    from_vault = await _vault_secret(name)
    if from_vault:
        return from_vault
    value = os.getenv(name, "")
    if not value:
        raise ValueError(f"Missing required secret: {name}")
    return value


async def _audit_api_call(provider: str, target: str) -> None:
    # Structured audit event can be forwarded to central logs/collector.
    print(f"AUDIT analyzer_api provider={provider} target={target}")


async def analyze_ip(value: str) -> dict[str, Any]:
    abuse_key = await _secret("ABUSEIPDB_API_KEY")
    ipinfo_token = await _secret("IPINFO_TOKEN")
    await _throttle("abuseipdb", 1.2)
    await _audit_api_call("abuseipdb", value)
    async with httpx.AsyncClient(timeout=20) as client:
        abuse = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": abuse_key, "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": 90},
        )
        abuse.raise_for_status()

        await _throttle("ipinfo", 0.8)
        await _audit_api_call("ipinfo", value)
        ipinfo = await client.get(f"https://ipinfo.io/{value}/json", params={"token": ipinfo_token})
        ipinfo.raise_for_status()
    score = int(abuse.json().get("data", {}).get("abuseConfidenceScore", 0))
    return {"abuseipdb": abuse.json(), "ipinfo": ipinfo.json(), "score": score, "confidence": 0.85}


async def analyze_domain(value: str) -> dict[str, Any]:
    w = whois.whois(value)
    dns_data = {}
    for rec in ["A", "MX", "TXT"]:
        try:
            dns_data[rec] = [str(r) for r in dns.resolver.resolve(value, rec)]
        except Exception:
            dns_data[rec] = []
    score = 70 if not dns_data.get("MX") else 30
    return {"whois": {k: str(v) for k, v in dict(w).items()}, "dns": dns_data, "score": score, "confidence": 0.7}


async def analyze_url(value: str) -> dict[str, Any]:
    gsb_key = await _secret("GOOGLE_SAFE_BROWSING_API_KEY")
    urlscan_key = await _secret("URLSCAN_API_KEY")
    body = {
        "client": {"clientId": "sirp", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": value}],
        },
    }
    async with httpx.AsyncClient(timeout=20) as client:
        await _throttle("google_safe_browsing", 1.0)
        await _audit_api_call("google_safe_browsing", value)
        gsb = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}", json=body
        )
        gsb.raise_for_status()

        await _throttle("urlscan", 1.5)
        await _audit_api_call("urlscan", value)
        scan = await client.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": urlscan_key},
            json={"url": value, "visibility": "private"},
        )
        scan.raise_for_status()
    malicious = bool(gsb.json().get("matches"))
    return {"safe_browsing": gsb.json(), "urlscan": scan.json(), "score": 90 if malicious else 35, "confidence": 0.8}


async def analyze_hash(value: str) -> dict[str, Any]:
    vt_key = await _secret("VIRUSTOTAL_API_KEY")
    mb_key = os.getenv("MALWAREBAZAAR_API_KEY", "")
    async with httpx.AsyncClient(timeout=20) as client:
        await _throttle("virustotal", 1.2)
        await _audit_api_call("virustotal", value)
        vt = await client.get(
            f"https://www.virustotal.com/api/v3/files/{value}", headers={"x-apikey": vt_key}
        )
        vt.raise_for_status()

        await _throttle("malwarebazaar", 1.0)
        await _audit_api_call("malwarebazaar", value)
        mb = await client.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": value, "api_key": mb_key},
        )
        mb.raise_for_status()
    stats = vt.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    bad = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    score = int((bad / total) * 100)
    return {"virustotal": vt.json(), "malwarebazaar": mb.json(), "score": score, "confidence": 0.9}


async def analyze_email(value: str) -> dict[str, Any]:
    # value is a plain email address string (e.g. "attacker@evil.com")
    parts = value.strip().split("@")
    from_domain = parts[-1] if len(parts) == 2 else ""
    domain = await analyze_domain(from_domain) if from_domain else {"score": 50, "confidence": 0.5}
    score = min(100, int((domain.get("score", 50) + 20) / 2))
    return {
        "email": value,
        "domain": from_domain,
        "domain_reputation": domain,
        "score": score,
        "confidence": 0.65,
    }


def aggregate_score(results: list[dict[str, Any]]) -> dict[str, Any]:
    weights = [0.3, 0.25, 0.2, 0.15, 0.1]
    scores = [r.get("score", 0) for r in results]
    scores += [0] * (len(weights) - len(scores))
    final = sum(w * s for w, s in zip(weights, scores))
    verdict = "malicious" if final >= 70 else "suspicious" if final >= 40 else "benign"
    return {"final_score": round(final, 2), "verdict": verdict}


async def run_analysis(job: dict[str, Any]) -> dict[str, Any]:
    t = job.get("type")
    v = job.get("value")
    if t == "ip":
        result = await analyze_ip(v)
    elif t == "domain":
        result = await analyze_domain(v)
    elif t == "url":
        result = await analyze_url(v)
    elif t == "hash":
        result = await analyze_hash(v)
    elif t == "email":
        result = await analyze_email(v)
    else:
        raise ValueError(f"Unsupported IOC type: {t}")
    return {"ioc_type": t, "value": v, "analysis": result, "risk": aggregate_score([result])}
