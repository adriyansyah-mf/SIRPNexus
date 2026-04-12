import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

import asyncpg
import httpx
from aiokafka import AIOKafkaProducer
from elasticsearch import AsyncElasticsearch
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from redis.asyncio import Redis

app = FastAPI(title="Alert Service")
Instrumentator().instrument(app).expose(app)

opencti_log = logging.getLogger("sirp.opencti")
abuseipdb_log = logging.getLogger("sirp.abuseipdb")

producer: AIOKafkaProducer | None = None
redis_client: Redis | None = None
es: AsyncElasticsearch | None = None
db_pool: asyncpg.Pool | None = None
opencti_sync_task = None
# Short-lived JWT from email/password login (when no PAT); avoids login on every request.
_opencti_login_jwt: str = ""
_opencti_login_jwt_at: float = 0.0
_OPENCTI_LOGIN_JWT_TTL_SEC = 600.0
ALERTS: list[dict[str, Any]] = []

KAFKA = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
ELASTIC_URL = os.getenv("ELASTICSEARCH_URL", "http://elastic:sirp@elasticsearch:9200")
_DEFAULT_INGEST_NETS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8"
INGEST_ALLOWLIST = [
    v.strip() for v in os.getenv("INGEST_ALLOWLIST", _DEFAULT_INGEST_NETS).split(",") if v.strip()
]
ALLOW_INSECURE_NO_INTERNAL_TOKEN = os.getenv("ALLOW_INSECURE_NO_INTERNAL_TOKEN", "").strip().lower() in (
    "1",
    "true",
    "yes",
)
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "").strip()
if not INTERNAL_SERVICE_TOKEN and not ALLOW_INSECURE_NO_INTERNAL_TOKEN:
    raise RuntimeError(
        "INTERNAL_SERVICE_TOKEN is required. Set ALLOW_INSECURE_NO_INTERNAL_TOKEN=1 for local dev only."
    )
SECRET_SERVICE_URL = os.getenv("SECRET_SERVICE_URL", "http://secret-service:8001")
ABUSEIPDB_API_BASE = os.getenv("ABUSEIPDB_API_BASE", "https://api.abuseipdb.com/api/v2").rstrip("/")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _allowed(ip: str) -> bool:
    ipa = ipaddress.ip_address(ip)
    return any(ipa in ipaddress.ip_network(c, strict=False) for c in INGEST_ALLOWLIST)


def _ingest_client_ip(request: Request) -> str:
    """Direct TCP client (e.g. api-gateway). For /ingest via gateway, use forwarded IP when trusted."""
    direct = request.client.host if request.client else "127.0.0.1"
    if not INTERNAL_SERVICE_TOKEN:
        return direct
    if request.headers.get("x-internal-token") != INTERNAL_SERVICE_TOKEN:
        return direct
    raw = request.headers.get("x-sirp-ingest-client-ip") or request.headers.get("X-SIRP-Ingest-Client-IP")
    if not raw:
        return direct
    candidate = raw.split(",")[0].strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return direct


_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False

def _extract_observables(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    def _add(t: str, v: str) -> None:
        key = f"{t}:{v}"
        if key not in seen:
            seen.add(key)
            out.append({"type": t, "value": v})

    for url in set(re.findall(r"https?://[^\s\"'<>]+", text)):
        _add("url", url.rstrip(".,;)"))
    for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)):
        if _is_public_ip(ip):
            _add("ip", ip)
    for e in set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)):
        _add("email", e.lower())
    for h in set(re.findall(r"\b[a-fA-F0-9]{64}\b", text)):
        _add("hash", h.lower())
    for h in set(re.findall(r"\b[a-fA-F0-9]{40}\b", text)):
        _add("hash", h.lower())
    for h in set(re.findall(r"\b[a-fA-F0-9]{32}\b", text)):
        _add("hash", h.lower())
    # Domain extraction — skip bare IPs and obvious filenames (eve.json, etc.)
    for domain in set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)):
        dl = domain.lower()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", dl):
            continue
        if re.search(r"\.(json|xml|log|txt|yml|yaml|js|css|sh|py|php|conf|cfg|ini)$", dl, re.I):
            continue
        _add("domain", dl)
    return out


def _wazuh_split_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Wazuh JSON has rule + agent at root; decoder fields live under data.{srcip,full_log,...}."""
    rule = dict(payload.get("rule") or {})
    agent = dict(payload.get("agent") or {})
    data_block = payload.get("data")
    data_kv: dict[str, Any] = {}
    if isinstance(data_block, dict):
        for k, v in data_block.items():
            if k == "rule" and isinstance(v, dict) and not rule:
                rule = dict(v)
            elif k == "agent" and isinstance(v, dict) and not agent:
                agent = dict(v)
            else:
                data_kv[k] = v
    return rule, agent, data_kv


def _wazuh_full_log_text(data_kv: dict[str, Any]) -> str:
    fl = data_kv.get("full_log")
    if isinstance(fl, str):
        return fl
    if isinstance(fl, (dict, list)):
        return json.dumps(fl, default=str)
    return ""


def _wazuh_tags_from_rule(rule: dict[str, Any]) -> list[str]:
    tags = ["wazuh"]
    groups = rule.get("groups")
    if isinstance(groups, str):
        groups = [groups]
    if isinstance(groups, list):
        for g in groups:
            if isinstance(g, str) and g.strip():
                g = g.strip()
                tags.append(g if len(g) <= 48 else g[:45] + "…")
    mitre_codes = re.findall(r"T\d{4}(?:\.\d{3})?", json.dumps(rule))
    for c in mitre_codes[:5]:
        if c not in tags:
            tags.append(c)
    # de-dupe preserve order
    return list(dict.fromkeys(tags))[:24]


def _wazuh_field_observables(data_kv: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(t: str, v: Any) -> None:
        if v is None:
            return
        s = str(v).strip()
        if not s or len(s) > 600:
            return
        key = f"{t}:{s.lower()}"
        if key in seen:
            return
        seen.add(key)
        out.append({"type": t, "value": s})

    pairs = [
        ("srcip", "ip"), ("dstip", "ip"), ("src_ip", "ip"), ("dst_ip", "ip"),
        ("srcport", "port"), ("dstport", "port"), ("src_port", "port"), ("dst_port", "port"),
        ("url", "url"), ("md5", "hash"), ("sha1", "hash"), ("sha256", "hash"),
        ("file", "file"), ("filename", "file"), ("process", "process"),
        ("command", "command"), ("dstuser", "user"), ("srcuser", "user"), ("user", "user"),
        ("dns_query", "domain"), ("domain", "domain"), ("hostname", "hostname"),
        ("data_win_system_computer", "hostname"), ("status", "other"),
    ]
    for k, t in pairs:
        if k in data_kv:
            add(t, data_kv[k])
    return out


def _wazuh_human_summary(
    rule: dict[str, Any],
    agent: dict[str, Any],
    data_kv: dict[str, Any],
    full_log: str,
) -> str:
    lines: list[str] = []
    rid = rule.get("id")
    if rid is not None:
        lines.append(f"Rule ID: {rid}")
    ag_name = agent.get("name")
    ag_ip = agent.get("ip")
    ag_id = agent.get("id")
    if ag_name or ag_ip or ag_id:
        parts = [str(x) for x in [ag_name, ag_ip] if x]
        if ag_id:
            parts.append(f"id {ag_id}")
        lines.append(f"Agent / endpoint: {' · '.join(parts)}")
    # Windows / decoder message fields
    for key in ("message", "win_message", "msg", "win_system_message"):
        v = data_kv.get(key)
        if isinstance(v, str) and v.strip():
            lines.append(v.strip()[:900])
            break
    detail_keys = [
        ("Destination user", "dstuser"),
        ("Source IP", "srcip"),
        ("Destination IP", "dstip"),
        ("Process", "process"),
        ("Command", "command"),
        ("File", "file"),
        ("URL", "url"),
        ("MD5", "md5"),
        ("SHA256", "sha256"),
        ("Registry", "registry_key"),
        ("Computer", "data_win_system_computer"),
    ]
    for label, key in detail_keys:
        v = data_kv.get(key)
        if isinstance(v, str) and v.strip():
            lines.append(f"{label}: {v.strip()[:280]}")
    if full_log and len("\n".join(lines)) < 80:
        snippet = full_log.replace("\r\n", "\n").strip()[:1500]
        if snippet:
            lines.append("— Raw event —\n" + snippet)
    elif full_log and len(lines) < 4:
        snippet = full_log.replace("\r\n", "\n").strip()[:1200]
        if snippet:
            lines.append("— Raw event —\n" + snippet)
    body = "\n".join(lines).strip()
    if not body:
        body = full_log.strip()[:2000] or json.dumps(data_kv, default=str)[:2000]
    return body[:2800]


def _wazuh_title(rule: dict[str, Any], data_kv: dict[str, Any], full_log: str) -> str:
    desc = (rule.get("description") or "").strip()
    if desc and desc.lower() not in ("wazuh alert", "local rule"):
        return desc[:240]
    for key in ("message", "win_message", "msg"):
        m = data_kv.get(key)
        if isinstance(m, str):
            m = m.strip()
            if len(m) > 12:
                return m[:240]
    if full_log:
        for ln in full_log.splitlines():
            s = ln.strip()
            if len(s) > 15 and not s.startswith("<"):
                return s[:240]
        return full_log.strip()[:240]
    return desc or "Wazuh alert"


def _normalize_wazuh(payload: dict[str, Any]) -> dict[str, Any]:
    rule, agent, data_kv = _wazuh_split_payload(payload)
    full_log = _wazuh_full_log_text(data_kv)
    level = int(rule.get("level") or data_kv.get("level") or 5)
    sev = "critical" if level >= 14 else "high" if level >= 10 else "medium" if level >= 7 else "low"
    title = _wazuh_title(rule, data_kv, full_log)
    summary = _wazuh_human_summary(rule, agent, data_kv, full_log)
    tags = _wazuh_tags_from_rule(rule)

    text_blob = f"{title}\n{summary}\n{full_log}\n{json.dumps(data_kv, default=str)}"
    obs = list({(o["type"], o["value"]): o for o in (_wazuh_field_observables(data_kv) + _extract_observables(text_blob))}.values())

    agent_block = {
        "id": str(agent.get("id", "") or ""),
        "name": str(agent.get("name", "") or ""),
        "ip": str(agent.get("ip", "") or ""),
    }
    rule_ref = {
        "id": rule.get("id"),
        "level": level,
        "groups": rule.get("groups") if isinstance(rule.get("groups"), (list, str)) else [],
        "description": rule.get("description"),
    }
    location = payload.get("location") or data_kv.get("location") or ""

    return {
        "source": "wazuh",
        "severity": sev,
        "title": title,
        "description": summary[:2000],
        "summary": summary,
        "raw": payload,
        "tags": tags,
        "observables": obs,
        "agent": agent_block,
        "rule_ref": rule_ref,
        "location": location,
    }


def _normalize_elastic(hit: dict[str, Any]) -> dict[str, Any]:
    src = hit.get("_source", {})
    sev = (src.get("kibana", {}).get("alert", {}).get("severity") or "medium").lower()
    if sev not in {"low", "medium", "high", "critical"}:
        sev = "medium"
    return {
        "source": "elastic",
        "severity": sev,
        "title": src.get("signal", {}).get("rule", {}).get("name", "Elastic SIEM alert"),
        "description": src.get("message", ""),
        "raw": src,
        "tags": ["elastic", "ecs"],
    }


def _normalize_splunk(row: dict[str, Any]) -> dict[str, Any]:
    sev = str(row.get("severity", "medium")).lower()
    if sev not in {"low", "medium", "high", "critical"}:
        sev = "medium"
    return {
        "source": "splunk",
        "severity": sev,
        "title": row.get("title", "Splunk alert"),
        "description": json.dumps(row)[:2000],
        "raw": row,
        "tags": ["splunk"],
    }


def _normalize_sentinel(item: dict[str, Any]) -> dict[str, Any]:
    props = item.get("properties", {})
    sev = str(props.get("severity", "medium")).lower()
    if sev not in {"low", "medium", "high", "critical"}:
        sev = "medium"
    return {
        "source": "sentinel",
        "severity": sev,
        "title": props.get("title", "Sentinel incident"),
        "description": props.get("description", "") or json.dumps(props)[:2000],
        "raw": item,
        "tags": ["sentinel", "azure"],
    }


def _opencti_entity_observables(entity: dict[str, Any]) -> list[dict[str, str]]:
    """Map STIX cyber-observable entity to IOC list for Kafka observables.created."""
    val = entity.get("observable_value") or entity.get("name")
    if not val or not str(val).strip():
        return []
    et = str(entity.get("entity_type") or "").upper()
    if "IPV4" in et or "IPV6" in et or et.endswith("IP"):
        t = "ip"
    elif "DOMAIN" in et:
        t = "domain"
    elif "HOST" in et or "HOSTNAME" in et:
        t = "hostname"
    elif "URL" in et:
        t = "url"
    elif "EMAIL" in et:
        t = "email"
    elif "FILE" in et or "HASH" in et or "STIXFILE" in et or "ARTIFACT" in et:
        t = "hash"
    else:
        t = "other"
    return [{"type": t, "value": str(val).strip()[:800]}]


def _normalize_opencti(entity: dict[str, Any]) -> dict[str, Any]:
    entity_type = entity.get("entity_type", "Stix-Cyber-Observable")
    description = entity.get("x_opencti_description") or entity.get("description") or ""
    confidence = int(entity.get("confidence", 50) or 50)
    score = "critical" if confidence >= 90 else "high" if confidence >= 75 else "medium"
    labels = [l.get("value") for l in entity.get("objectLabel", []) if l.get("value")]
    return {
        "source": "opencti",
        "severity": score,
        "title": f"OpenCTI {entity_type}: {entity.get('observable_value') or entity.get('name') or entity.get('id')}",
        "description": description[:2000],
        "raw": entity,
        "tags": ["opencti", entity_type.lower(), *labels],
        "observables": _opencti_entity_observables(entity),
    }


async def _publish(topic: str, payload: dict[str, Any]):
    assert producer
    await producer.send_and_wait(topic, json.dumps(payload, default=str).encode())


async def _secret_value(name: str) -> str:
    headers = {"x-internal-token": INTERNAL_SERVICE_TOKEN} if INTERNAL_SERVICE_TOKEN else {}
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(f"{SECRET_SERVICE_URL}/secrets/{name}", headers=headers)
            if resp.status_code == 200:
                return str(resp.json().get("value", ""))
    except Exception:
        pass
    return os.getenv(name, "")


def _opencti_debug_enabled() -> bool:
    return os.getenv("OPENCTI_DEBUG_LOG", "").lower() in ("1", "true", "yes")


def _oc_dbg(msg: str, *args: object) -> None:
    if _opencti_debug_enabled():
        opencti_log.info("[opencti] " + msg, *args)


async def _secret_get_http_only(name: str) -> str:
    """Read secret from secret-service only (no os.getenv). Used after env so .env wins over stale DB rows."""
    if not INTERNAL_SERVICE_TOKEN:
        if _opencti_debug_enabled() and name.startswith("OPENCTI"):
            _oc_dbg("secret-service: INTERNAL_SERVICE_TOKEN empty; cannot fetch %s", name)
        return ""
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(
                f"{SECRET_SERVICE_URL}/secrets/{name}",
                headers={"x-internal-token": INTERNAL_SERVICE_TOKEN},
            )
            if _opencti_debug_enabled() and name.startswith("OPENCTI"):
                _oc_dbg("secret-service GET /secrets/%s -> HTTP %s", name, resp.status_code)
            if resp.status_code == 200:
                return str(resp.json().get("value", ""))
    except Exception as exc:
        if _opencti_debug_enabled() and name.startswith("OPENCTI"):
            _oc_dbg("secret-service GET /secrets/%s failed: %s", name, exc)
    return ""


async def _opencti_config_str(key: str) -> str:
    """OpenCTI settings: non-empty environment variable wins over secret-service (avoids bad DB token masking good .env)."""
    v = (os.getenv(key, "") or "").strip()
    if v:
        _oc_dbg("config %s: source=env len=%d", key, len(v))
        return v
    sv = (await _secret_get_http_only(key)).strip()
    if sv:
        _oc_dbg("config %s: source=secret-service len=%d", key, len(sv))
        return sv
    _oc_dbg("config %s: empty (no env value, secret missing or empty)", key)
    return ""


def _opencti_normalize_pat(raw: str) -> str:
    """Strip whitespace, BOM, a single leading 'Bearer ', and internal newlines from pasted tokens."""
    t = (raw or "").strip().lstrip("\ufeff")
    if len(t) >= 7 and t[:7].lower() == "bearer ":
        t = t[7:].strip()
    t = "".join(t.split())  # remove spaces/newlines inside UUID/token pastes
    return t


async def _opencti_pat_from_store() -> str:
    for key in ("OPENCTI_TOKEN", "OPENCTI_API_KEY"):
        raw = await _opencti_config_str(key)
        v = _opencti_normalize_pat(raw)
        if v:
            _oc_dbg("PAT chosen from key=%s normalized_len=%d", key, len(v))
            return v
    _oc_dbg("no PAT from OPENCTI_TOKEN / OPENCTI_API_KEY")
    return ""


OPENCTI_AUTH_HINT = (
    "Use a Personal Access Token from OpenCTI (avatar → Profile → API / access tokens). "
    "Environment variables OPENCTI_TOKEN / OPENCTI_API_KEY override secret-service if both are set (fix stale DB entries). "
    "Store the raw token only (no 'Bearer ' prefix). Connector IDs are not user tokens. "
    "Or set OPENCTI_USER + OPENCTI_PASSWORD for GraphQL login."
)


async def _opencti_resolve_bearer(base_url: str) -> str:
    """Bearer token: PAT from secrets/env, else short-lived JWT from email/password GraphQL login."""
    global _opencti_login_jwt, _opencti_login_jwt_at
    pat = await _opencti_pat_from_store()
    if pat:
        _oc_dbg("auth: using personal access token (Bearer len=%d)", len(pat))
        return pat
    now = time.monotonic()
    if _opencti_login_jwt and (now - _opencti_login_jwt_at) < _OPENCTI_LOGIN_JWT_TTL_SEC:
        _oc_dbg("auth: using cached GraphQL-login JWT (len=%d, age_s=%.0f)", len(_opencti_login_jwt), now - _opencti_login_jwt_at)
        return _opencti_login_jwt
    email = (await _opencti_config_str("OPENCTI_USER")) or (await _opencti_config_str("OPENCTI_EMAIL"))
    if not email:
        email = (os.getenv("OPENCTI_USER") or os.getenv("OPENCTI_EMAIL") or "").strip()
    password = (await _opencti_config_str("OPENCTI_PASSWORD")).strip()
    if not email or not password:
        _oc_dbg("auth: no PAT and no OPENCTI_USER/PASSWORD for GraphQL login")
        return ""
    dom = email.split("@", 1)[-1] if "@" in email else "?"
    _oc_dbg(
        "auth: GraphQL token() login (email_len=%d domain=%s password_len=%d)",
        len(email),
        dom,
        len(password),
    )
    login_body: dict[str, Any] = {
        "query": "mutation OpenctiLogin($input: UserLoginInput!) { token(input: $input) }",
        "variables": {"input": {"email": email, "password": password}},
    }
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(
                f"{base_url}/graphql",
                json=login_body,
                headers={"Content-Type": "application/json"},
            )
        except httpx.RequestError as exc:
            _oc_dbg("GraphQL login request error: %s", exc)
            raise HTTPException(status_code=502, detail=f"OpenCTI login unreachable: {exc}") from exc
    _oc_dbg("GraphQL login HTTP status=%s", resp.status_code)
    if resp.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"OpenCTI login HTTP {resp.status_code}: {resp.text[:500]}",
        )
    body = resp.json()
    errs = body.get("errors")
    if errs:
        _oc_dbg("GraphQL login errors: %s", json.dumps(errs, default=str)[:1500])
        raise HTTPException(status_code=502, detail=f"OpenCTI login failed: {errs}")
    tok = body.get("data", {}).get("token")
    if not tok:
        raise HTTPException(status_code=502, detail="OpenCTI login returned empty token")
    jwt = _opencti_normalize_pat(str(tok))
    _opencti_login_jwt = jwt
    _opencti_login_jwt_at = now
    _oc_dbg("GraphQL login OK, JWT len=%d", len(jwt))
    return jwt


async def _opencti_post_graphql(
    base_url: str,
    gql_payload: dict[str, Any],
    *,
    raise_on_graphql_error: bool = True,
) -> dict[str, Any]:
    bearer = await _opencti_resolve_bearer(base_url)
    if not bearer:
        _oc_dbg("graphql aborted: no bearer (set OPENCTI_TOKEN / OPENCTI_API_KEY or OPENCTI_USER+OPENCTI_PASSWORD)")
        raise HTTPException(
            status_code=400,
            detail=f"OpenCTI authentication missing. {OPENCTI_AUTH_HINT}",
        )
    headers = {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"}
    op = (gql_payload.get("query") or "")[:80].replace("\n", " ")
    _oc_dbg("graphql POST %s/graphql op≈%r bearer_len=%d", base_url, op, len(bearer))
    async with httpx.AsyncClient(timeout=45) as client:
        try:
            resp = await client.post(f"{base_url}/graphql", json=gql_payload, headers=headers)
        except httpx.RequestError as exc:
            _oc_dbg("graphql transport error: %s", exc)
            raise HTTPException(status_code=502, detail=f"OpenCTI unreachable: {exc}") from exc
    _oc_dbg("graphql HTTP status=%s body_len=%d", resp.status_code, len(resp.content or b""))
    if resp.status_code >= 400:
        _oc_dbg("graphql error body (truncated): %s", (resp.text or "")[:500])
        raise HTTPException(
            status_code=502,
            detail=f"OpenCTI HTTP {resp.status_code}: {resp.text[:800]}",
        )
    payload = resp.json()
    gql_errs = payload.get("errors")
    if gql_errs:
        _oc_dbg("graphql response errors: %s", json.dumps(gql_errs, default=str)[:2000])
    elif _opencti_debug_enabled():
        data_keys = list((payload.get("data") or {}).keys())
        _oc_dbg("graphql OK data keys=%s", data_keys)
    if raise_on_graphql_error:
        errs = payload.get("errors")
        if errs:
            auth_fail = any(
                isinstance(e, dict) and (e.get("extensions") or {}).get("code") == "AUTH_REQUIRED"
                for e in errs
            )
            hint = f" {OPENCTI_AUTH_HINT}" if auth_fail else ""
            raise HTTPException(
                status_code=502,
                detail=f"OpenCTI GraphQL error:{hint} {json.dumps(errs, default=str)[:1200]}",
            )
    return payload


def _compute_risk_score(alert: dict[str, Any]) -> int:
    """Heuristic 0–100 for SOC queue prioritization (severity + IOC density + tags)."""
    sev = str(alert.get("severity", "")).lower()
    base = {"low": 18, "medium": 42, "high": 68, "critical": 92}.get(sev, 38)
    obs = alert.get("observables")
    n_obs = len(obs) if isinstance(obs, list) else 0
    tags = alert.get("tags")
    n_tags = len(tags) if isinstance(tags, list) else 0
    bonus = min(28, n_obs * 4 + min(8, n_tags * 2))
    return min(100, base + bonus)


async def _ingest(normalized: dict[str, Any]) -> dict[str, Any]:
    text = f"{normalized['title']} {normalized['description']} {normalized.get('summary', '')} {json.dumps(normalized['raw'])}"
    regex_obs = _extract_observables(text)
    existing = normalized.get("observables")
    if isinstance(existing, list) and existing:
        merged: dict[tuple[str | None, str | None], dict[str, str]] = {}
        for o in existing:
            if isinstance(o, dict) and o.get("value"):
                merged[(o.get("type"), str(o.get("value")))] = {"type": str(o.get("type", "other")), "value": str(o["value"])}
        for o in regex_obs:
            k = (o.get("type"), o.get("value"))
            merged.setdefault(k, o)
        normalized["observables"] = list(merged.values())
    else:
        normalized["observables"] = regex_obs
    normalized["risk_score"] = _compute_risk_score(normalized)
    normalized["status"] = normalized.get("status", "new")
    ts = _now()
    normalized["ingested_at"] = ts
    normalized["created_at"] = ts
    normalized["id"] = hashlib.sha256(
        f"{normalized['source']}|{normalized['title']}|{normalized['description']}".encode()
    ).hexdigest()

    assert redis_client and es
    dedupe_key = f"alert:dedupe:{normalized['id']}"
    if not await redis_client.set(dedupe_key, "1", ex=3600, nx=True):
        return {"status": "duplicate", "id": normalized["id"]}

    ALERTS.append(normalized)
    if db_pool:
        await db_pool.execute(
            "INSERT INTO alerts(id, payload, created_at) VALUES($1, $2::jsonb, now()) "
            "ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload",
            normalized["id"],
            json.dumps(normalized),
        )
    await _publish("alerts.ingested", normalized)
    await _publish("alerts.normalized", normalized)
    for ob in normalized["observables"]:
        await _publish("observables.created", {"alert_id": normalized["id"], **ob})
    await es.index(index="alerts", id=normalized["id"], document=normalized)
    return normalized


async def _pull_opencti(limit: int = 100) -> int:
    base_url = (await _opencti_config_str("OPENCTI_URL")).strip().rstrip("/")
    if not base_url:
        raise HTTPException(status_code=400, detail="OpenCTI configuration missing: OPENCTI_URL")
    _oc_dbg("pull_opencti start base_url=%s limit=%d", base_url, limit)

    query = """
    query ListObservables($first: Int!) {
      stixCyberObservables(first: $first, orderBy: updated_at, orderMode: desc) {
        edges {
          node {
            id
            entity_type
            observable_value
            x_opencti_description
            created_at
            updated_at
            objectLabel {
              edges {
                node {
                  value
                }
              }
            }
          }
        }
      }
    }
    """

    payload = await _opencti_post_graphql(
        base_url,
        {"query": query, "variables": {"first": limit}},
    )

    edges = payload.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
    ingested = 0
    for edge in edges:
        node = edge.get("node", {})
        labels = node.get("objectLabel", {}).get("edges", [])
        node["objectLabel"] = [entry.get("node", {}) for entry in labels]
        out = await _ingest(_normalize_opencti(node))
        if out.get("status") != "duplicate":
            ingested += 1
    _oc_dbg("pull_opencti done edges=%d new_ingested=%d", len(edges), ingested)
    return ingested


_OPENCTI_LOOKUP_QUERY = """
query OpenctiObservableLookup($search: String!, $first: Int!) {
  stixCyberObservables(search: $search, first: $first, orderBy: updated_at, orderMode: desc) {
    edges {
      node {
        id
        standard_id
        entity_type
        observable_value
        x_opencti_description
        created_at
        updated_at
      }
    }
    pageInfo {
      globalCount
    }
  }
}
"""


async def _opencti_graphql_lookup(search_term: str, first: int = 20) -> dict[str, Any]:
    """Call OpenCTI GraphQL stixCyberObservables(search=...) — same /graphql as bulk pull."""
    base_url = (await _opencti_config_str("OPENCTI_URL")).strip().rstrip("/")
    if not base_url:
        raise HTTPException(
            status_code=400,
            detail="OpenCTI not configured: set OPENCTI_URL (secret-service or env on alert-service)",
        )
    st = search_term.strip()
    if not st:
        raise HTTPException(status_code=400, detail="value required")
    first = max(1, min(int(first), 50))
    gql_body = {
        "query": _OPENCTI_LOOKUP_QUERY,
        "variables": {"search": st, "first": first},
    }
    payload = await _opencti_post_graphql(base_url, gql_body, raise_on_graphql_error=False)
    gql_errors = payload.get("errors")
    conn = (payload.get("data") or {}).get("stixCyberObservables") or {}
    edges = conn.get("edges") or []
    matches: list[dict[str, Any]] = []
    for edge in edges:
        n = edge.get("node") or {}
        matches.append(
            {
                "id": n.get("id"),
                "standard_id": n.get("standard_id"),
                "entity_type": n.get("entity_type"),
                "observable_value": n.get("observable_value"),
                "description": n.get("x_opencti_description"),
                "created_at": n.get("created_at"),
                "updated_at": n.get("updated_at"),
            }
        )
    auth_hint = None
    if gql_errors and isinstance(gql_errors, list):
        if any(
            isinstance(e, dict) and (e.get("extensions") or {}).get("code") == "AUTH_REQUIRED"
            for e in gql_errors
        ):
            auth_hint = OPENCTI_AUTH_HINT
    _oc_dbg(
        "lookup done search_len=%d first=%d matches=%d graphql_errors=%s auth_hint=%s",
        len(st),
        first,
        len(matches),
        bool(gql_errors),
        bool(auth_hint),
    )
    return {
        "search": st,
        "matches": matches,
        "page_info": conn.get("pageInfo"),
        "graphql_errors": gql_errors,
        "auth_hint": auth_hint,
    }


async def _abuseipdb_api_key() -> str:
    """Personal API key from AbuseIPDB account; env overrides secret-service (same rule as OpenCTI)."""
    v = (os.getenv("ABUSEIPDB_API_KEY", "") or "").strip()
    if v:
        return v
    return (await _secret_get_http_only("ABUSEIPDB_API_KEY")).strip()


def _parse_ip_for_abuseipdb(raw: str) -> str:
    v = (raw or "").strip()
    if not v:
        raise HTTPException(status_code=400, detail="value required")
    try:
        return str(ipaddress.ip_address(v))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="AbuseIPDB accepts IPv4/IPv6 only (not domains, URLs, or hashes).",
        ) from exc


async def _abuseipdb_check_ip(ip: str, max_age_days: int) -> dict[str, Any]:
    key = await _abuseipdb_api_key()
    if not key:
        raise HTTPException(
            status_code=400,
            detail="AbuseIPDB not configured: set ABUSEIPDB_API_KEY (environment or secret-service).",
        )
    params = {"ipAddress": ip, "maxAgeInDays": max(1, min(int(max_age_days), 365))}
    headers = {"Key": key, "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=25) as client:
        try:
            resp = await client.get(f"{ABUSEIPDB_API_BASE}/check", params=params, headers=headers)
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"AbuseIPDB unreachable: {exc}") from exc
    try:
        body = resp.json()
    except Exception:
        body = {}
    if resp.status_code >= 400:
        errs = body.get("errors") if isinstance(body, dict) else None
        detail = (
            json.dumps(errs, default=str)[:800]
            if errs
            else (resp.text or "")[:800]
            or f"HTTP {resp.status_code}"
        )
        raise HTTPException(status_code=502, detail=f"AbuseIPDB API error: {detail}")
    if not isinstance(body, dict):
        raise HTTPException(status_code=502, detail="AbuseIPDB returned invalid JSON")
    return {
        "source": "abuseipdb",
        "ip": ip,
        "data": body.get("data"),
        "api_errors": body.get("errors"),
    }


def _normalize_abuseipdb_blacklist_row(row: dict[str, Any]) -> dict[str, Any]:
    score = int(row.get("abuseConfidenceScore") or 0)
    sev = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    ip = str(row.get("ipAddress") or "")
    return {
        "source": "abuseipdb",
        "severity": sev,
        "title": f"AbuseIPDB blacklist: {ip} (score {score})",
        "description": (
            f"Country: {row.get('countryCode', '')}. Last reported: {row.get('lastReportedAt', '')}"
        )[:2000],
        "raw": row,
        "tags": ["abuseipdb", "blacklist", "ip"],
    }


async def _pull_abuseipdb_blacklist(limit: int = 100, confidence_minimum: int = 90) -> int:
    key = await _abuseipdb_api_key()
    if not key:
        raise HTTPException(
            status_code=400,
            detail="ABUSEIPDB_API_KEY required for AbuseIPDB blacklist pull.",
        )
    lim = max(1, min(int(limit), 10_000))
    conf = max(25, min(int(confidence_minimum), 100))
    params = {"confidenceMinimum": conf, "limit": lim}
    headers = {"Key": key, "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=90) as client:
        try:
            resp = await client.get(f"{ABUSEIPDB_API_BASE}/blacklist", params=params, headers=headers)
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"AbuseIPDB unreachable: {exc}") from exc
    try:
        body = resp.json()
    except Exception:
        body = {}
    if resp.status_code >= 400:
        errs = body.get("errors") if isinstance(body, dict) else None
        detail = (
            json.dumps(errs, default=str)[:800]
            if errs
            else (resp.text or "")[:800]
            or f"HTTP {resp.status_code}"
        )
        raise HTTPException(status_code=502, detail=f"AbuseIPDB blacklist failed: {detail}")
    rows = body.get("data") if isinstance(body, dict) else None
    if not isinstance(rows, list):
        rows = []
    ingested = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        out = await _ingest(_normalize_abuseipdb_blacklist_row(row))
        if out.get("status") != "duplicate":
            ingested += 1
    abuseipdb_log.info("abuseipdb blacklist pull: rows=%d new_ingested=%d", len(rows), ingested)
    return ingested


async def _threat_intel_sync_loop():
    interval = int(os.getenv("OPENCTI_AUTO_SYNC_INTERVAL_SECONDS", "300"))
    limit_oc = int(os.getenv("OPENCTI_QUERY_LIMIT", "100"))
    limit_abi = int(os.getenv("ABUSEIPDB_BLACKLIST_LIMIT", "100"))
    conf_min = int(os.getenv("ABUSEIPDB_CONFIDENCE_MINIMUM", "90"))
    src = os.getenv("THREAT_INTEL_PULL_SOURCE", "opencti").lower().strip()
    while True:
        if src in ("opencti", "both"):
            try:
                await _pull_opencti(limit=limit_oc)
            except Exception as exc:
                _oc_dbg("auto-sync OpenCTI pull failed: %s", repr(exc)[:400])
        if src in ("abuseipdb", "both"):
            try:
                await _pull_abuseipdb_blacklist(limit=limit_abi, confidence_minimum=conf_min)
            except Exception as exc:
                abuseipdb_log.warning("auto-sync AbuseIPDB pull failed: %s", repr(exc)[:400])
        await asyncio.sleep(interval)


def _alert_payload_from_db(raw: Any) -> dict[str, Any] | None:
    """JSONB from Postgres may be dict or (with some setups) a JSON string."""
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return dict(decoded) if isinstance(decoded, dict) else None
    if isinstance(raw, (bytes, bytearray)):
        try:
            decoded = json.loads(raw.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return dict(decoded) if isinstance(decoded, dict) else None
    return None


async def _get_alert_or_404(alert_id: str) -> dict[str, Any]:
    alert = next((a for a in ALERTS if a.get("id") == alert_id), None)
    if not alert and db_pool:
        row = await db_pool.fetchrow("SELECT payload FROM alerts WHERE id = $1", alert_id)
        if row:
            alert = _alert_payload_from_db(row["payload"])
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if "risk_score" not in alert:
        alert["risk_score"] = _compute_risk_score(alert)
    return alert


@app.on_event("startup")
async def startup():
    global producer, redis_client, es, db_pool, opencti_sync_task
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA)
    await producer.start()
    redis_client = Redis.from_url(os.getenv("REDIS_URL", "redis://:sirp@redis:6379/0"))
    es = AsyncElasticsearch(hosts=[ELASTIC_URL])
    db_pool = await asyncpg.create_pool(
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        user=os.getenv("POSTGRES_USER", "sirp"),
        password=os.getenv("POSTGRES_PASSWORD", "sirp"),
        database=os.getenv("POSTGRES_DB", "sirp"),
        min_size=1,
        max_size=5,
    )
    await db_pool.execute(
        "CREATE TABLE IF NOT EXISTS alerts ("
        "id TEXT PRIMARY KEY, payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
    )
    if _opencti_debug_enabled():
        opencti_log.info(
            "[opencti] OPENCTI_DEBUG_LOG enabled — logger=%s (no secrets logged)",
            opencti_log.name,
        )
    if os.getenv("OPENCTI_AUTO_SYNC_ENABLED", "false").lower() == "true":
        opencti_sync_task = asyncio.create_task(_threat_intel_sync_loop())


@app.on_event("shutdown")
async def shutdown():
    global opencti_sync_task
    if producer:
        await producer.stop()
    if redis_client:
        await redis_client.close()
    if es:
        await es.close()
    if db_pool:
        await db_pool.close()
    if opencti_sync_task:
        opencti_sync_task.cancel()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/opencti/lookup")
async def opencti_lookup(body: dict[str, Any]):
    """Lookup IOC in OpenCTI via POST {OPENCTI_URL}/graphql (stixCyberObservables search)."""
    val = body.get("value")
    if val is None or str(val).strip() == "":
        raise HTTPException(status_code=400, detail="value required")
    try:
        first = int(body.get("first", 20))
    except (TypeError, ValueError):
        first = 20
    return await _opencti_graphql_lookup(str(val).strip(), first=first)


@app.post("/abuseipdb/lookup")
async def abuseipdb_lookup(body: dict[str, Any]):
    """IP reputation check via AbuseIPDB GET /check (requires ABUSEIPDB_API_KEY)."""
    val = body.get("value")
    if val is None or str(val).strip() == "":
        raise HTTPException(status_code=400, detail="value required")
    try:
        max_age = int(body.get("maxAgeInDays", 90))
    except (TypeError, ValueError):
        max_age = 90
    ip = _parse_ip_for_abuseipdb(str(val))
    return await _abuseipdb_check_ip(ip, max_age)


@app.middleware("http")
async def enforce_internal_token(request: Request, call_next):
    if request.url.path in {"/health", "/metrics"} or request.url.path.startswith("/alerts/webhook/"):
        return await call_next(request)
    if not INTERNAL_SERVICE_TOKEN.strip():
        if ALLOW_INSECURE_NO_INTERNAL_TOKEN:
            return await call_next(request)
        return JSONResponse(status_code=503, content={"detail": "INTERNAL_SERVICE_TOKEN is not configured"})
    if request.headers.get("x-internal-token") != INTERNAL_SERVICE_TOKEN:
        return JSONResponse(status_code=401, content={"detail": "Invalid internal service token"})
    return await call_next(request)


@app.get("/alerts/siem-retro-search")
async def siem_retro_search(q: str, size: int = 40, index: str | None = None):
    """Full-text retro-hunt against Elasticsearch (e.g. Wazuh / ECS indices)."""
    if es is None:
        raise HTTPException(status_code=503, detail="Elasticsearch not available")
    qn = (q or "").strip()
    if len(qn) < 2:
        raise HTTPException(status_code=400, detail="q must be at least 2 characters")
    sz = max(1, min(int(size), 100))
    idx = (index or os.getenv("ELASTIC_SIEM_INDEX", "wazuh-alerts-*")).strip() or "wazuh-alerts-*"
    try:
        resp = await es.search(
            index=idx,
            size=sz,
            query={"simple_query_string": {"query": qn, "fields": ["*"], "default_operator": "or"}},
            sort=[{"@timestamp": {"order": "desc"}}],
        )
    except Exception as exc:
        err = str(exc)[:240]
        return {"index": idx, "query": qn, "hits": [], "error": err, "note": "ES query failed — check index pattern ELASTIC_SIEM_INDEX"}
    hits_out: list[dict[str, Any]] = []
    for h in resp.get("hits", {}).get("hits", []) or []:
        src = h.get("_source") if isinstance(h.get("_source"), dict) else {}
        msg = None
        if isinstance(src.get("rule"), dict):
            msg = src["rule"].get("description")
        if msg is None:
            msg = src.get("full_log") or src.get("message")
        if msg is None:
            msg = str(src.get("data", ""))[:400]
        hits_out.append(
            {
                "_id": h.get("_id"),
                "_index": h.get("_index"),
                "@timestamp": src.get("@timestamp"),
                "summary": str(msg or "")[:500],
            }
        )
    total = resp.get("hits", {}).get("total", {})
    if isinstance(total, dict):
        total_v = total.get("value", len(hits_out))
    else:
        total_v = total
    return {"index": idx, "query": qn, "total": total_v, "hits": hits_out}


@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    return await _get_alert_or_404(alert_id)


@app.delete("/alerts/{alert_id}")
async def delete_alert(alert_id: str):
    alert = await _get_alert_or_404(alert_id)
    if db_pool:
        await db_pool.execute("DELETE FROM alerts WHERE id = $1", alert_id)
    # Remove from dedupe cache
    if redis_client:
        await redis_client.delete(f"alert:dedupe:{alert_id}")
    # Remove from in-memory list
    global ALERTS
    ALERTS = [a for a in ALERTS if a.get("id") != alert_id]
    return {"status": "deleted", "id": alert_id, "title": alert.get("title")}


async def _all_alerts_payloads() -> list[dict[str, Any]]:
    if db_pool:
        rows = await db_pool.fetch("SELECT payload FROM alerts ORDER BY created_at DESC LIMIT 1000")
        out: list[dict[str, Any]] = []
        for row in rows:
            payload = row["payload"]
            if isinstance(payload, dict):
                out.append(payload)
            elif isinstance(payload, str):
                try:
                    decoded = json.loads(payload)
                    if isinstance(decoded, dict):
                        out.append(decoded)
                except Exception:
                    continue
        return out
    return list(ALERTS)


@app.get("/alerts")
async def list_alerts():
    out = await _all_alerts_payloads()
    for a in out:
        if isinstance(a, dict) and "risk_score" not in a:
            a["risk_score"] = _compute_risk_score(a)
    return out


@app.delete("/alerts")
async def delete_all_alerts():
    """Remove every alert from Postgres, in-memory cache, and Redis dedupe keys."""
    global ALERTS
    n_db = 0
    if db_pool:
        n_db = int(await db_pool.fetchval("SELECT count(*) FROM alerts") or 0)
        await db_pool.execute("DELETE FROM alerts")
    ALERTS.clear()
    redis_deleted = 0
    if redis_client:
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor=cursor, match="alert:dedupe:*", count=400)
            if keys:
                await redis_client.delete(*keys)
                redis_deleted += len(keys)
            if cursor == 0:
                break
    return {"status": "purged", "removed_db": n_db, "redis_dedupe_keys_deleted": redis_deleted}


@app.get("/alerts/{alert_id}/related")
async def related_alerts(alert_id: str, limit: int = 25):
    """Other alerts that share at least one observable value (type-insensitive match on value)."""
    me = await _get_alert_or_404(alert_id)
    obs_me = {
        (str(o.get("type", "other")), str(o.get("value", ""))[:500])
        for o in (me.get("observables") or [])
        if isinstance(o, dict) and o.get("value")
    }
    if not obs_me:
        return {"alerts": []}
    limit = max(1, min(limit, 100))
    hits: list[dict[str, Any]] = []
    for a in await _all_alerts_payloads():
        aid = str(a.get("id", ""))
        if aid == alert_id:
            continue
        o2 = {
            (str(o.get("type", "other")), str(o.get("value", ""))[:500])
            for o in (a.get("observables") or [])
            if isinstance(o, dict) and o.get("value")
        }
        shared = obs_me & o2
        if shared:
            hits.append(
                {
                    "id": aid,
                    "title": a.get("title"),
                    "overlap": len(shared),
                    "created_at": a.get("created_at"),
                    "source": a.get("source"),
                }
            )
    hits.sort(key=lambda x: -int(x.get("overlap") or 0))
    return {"alerts": hits[:limit]}


@app.post("/alerts/{alert_id}/assign")
async def assign_alert(alert_id: str, body: dict[str, str]):
    alert = await _get_alert_or_404(alert_id)
    alert["assigned_to"] = body.get("assigned_to")
    alert["assigned_by"] = body.get("assigned_by")
    alert["assigned_at"] = _now()
    if db_pool:
        await db_pool.execute(
            "UPDATE alerts SET payload = $2::jsonb WHERE id = $1",
            alert_id,
            json.dumps(alert),
        )
    return alert


@app.post("/alerts/{alert_id}/tags")
async def add_tags(alert_id: str, body: dict[str, list[str]]):
    alert = await _get_alert_or_404(alert_id)
    tags = set(alert.get("tags", []))
    for tag in body.get("tags", []):
        tags.add(tag)
    alert["tags"] = sorted(tags)
    if db_pool:
        await db_pool.execute(
            "UPDATE alerts SET payload = $2::jsonb WHERE id = $1",
            alert_id,
            json.dumps(alert),
        )
    return alert


@app.post("/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, body: dict[str, str]):
    alert = await _get_alert_or_404(alert_id)
    new_status = body.get("status", "new")
    if new_status not in {"new", "triaged", "escalated", "closed"}:
        raise HTTPException(status_code=400, detail="Invalid alert status")
    alert["status"] = new_status
    if db_pool:
        await db_pool.execute(
            "UPDATE alerts SET payload = $2::jsonb WHERE id = $1",
            alert_id,
            json.dumps(alert),
        )
    return alert


def _sanitize_observables(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        v = item.get("value")
        if v is None or v == "":
            continue
        out.append({"type": str(item.get("type") or "other"), "value": str(v)[:800]})
    return out


@app.post("/alerts/{alert_id}/escalate")
async def escalate_alert(alert_id: str):
    alert = await _get_alert_or_404(alert_id)
    if alert.get("status") == "escalated" and alert.get("case_id"):
        return {"status": "already_escalated", "case_id": alert["case_id"], "case": {"id": alert["case_id"]}}

    title = (alert.get("title") or "").strip() or "Untitled"
    description = alert.get("description") or alert.get("summary") or ""
    if not isinstance(description, str):
        description = json.dumps(description, default=str)
    sev = str(alert.get("severity") or "medium").lower()
    if sev not in {"low", "medium", "high", "critical"}:
        sev = "medium"
    tags_raw = alert.get("tags") or []
    tags = [str(t) for t in tags_raw if t is not None][:64] if isinstance(tags_raw, list) else []

    case_payload = {
        "alert_id": str(alert_id),
        "title": title[:500],
        "description": description[:16000],
        "observables": _sanitize_observables(alert.get("observables")),
        "tags": tags,
        "severity": sev,
    }
    case_base = os.getenv("CASE_SERVICE_URL", "http://case-service:8001").rstrip("/")
    url = f"{case_base}/cases/from-alert"
    headers: dict[str, str] = {"content-type": "application/json"}
    if INTERNAL_SERVICE_TOKEN:
        headers["x-internal-token"] = INTERNAL_SERVICE_TOKEN
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(url, json=case_payload, headers=headers)
        except httpx.ConnectError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Case service unreachable at {case_base}. Check CASE_SERVICE_URL and Docker network.",
            ) from exc
        if resp.status_code >= 400:
            detail = resp.text[:800] if resp.text else resp.reason_phrase
            raise HTTPException(
                status_code=502,
                detail=f"Case service error {resp.status_code}: {detail}",
            )
        case = resp.json()

    alert["status"] = "escalated"
    alert["case_id"] = case["id"]
    if db_pool:
        await db_pool.execute(
            "UPDATE alerts SET payload = $2::jsonb WHERE id = $1",
            alert_id,
            json.dumps(alert),
        )
    return {"status": "escalated", "case": case}


@app.post("/alerts/webhook/{source}")
async def webhook_ingest(source: str, request: Request):
    client_ip = _ingest_client_ip(request)
    if not _allowed(client_ip):
        raise HTTPException(status_code=403, detail="IP not allowlisted")

    payload = await request.json()
    if source == "wazuh":
        normalized = _normalize_wazuh(payload)
    elif source == "splunk":
        normalized = _normalize_splunk(payload)
    elif source == "generic":
        normalized = {
            "source": payload.get("source", "generic"),
            "severity": payload.get("severity", "medium"),
            "title": payload.get("title", "Generic SIEM alert"),
            "description": payload.get("description", ""),
            "raw": payload,
            "tags": payload.get("tags", ["generic"]),
        }
    else:
        raise HTTPException(status_code=400, detail="Unsupported source")

    result = await _ingest(normalized)
    return {"status": "ok", "alert": result}


@app.post("/connectors/pull/wazuh")
async def pull_wazuh(limit: int = 100):
    url = await _secret_value("WAZUH_URL")
    user = await _secret_value("WAZUH_USER")
    pwd = await _secret_value("WAZUH_PASSWORD")
    if not all([url, user, pwd]):
        raise HTTPException(status_code=400, detail="Wazuh credentials missing")

    # verify=False only if WAZUH_VERIFY_TLS=false (self-signed certs on private network)
    verify_tls = os.getenv("WAZUH_VERIFY_TLS", "true").lower() != "false"
    async with httpx.AsyncClient(verify=verify_tls, timeout=30) as client:
        token_resp = await client.get(f"{url}/security/user/authenticate", auth=(user, pwd))
        token_resp.raise_for_status()
        token = token_resp.text.strip('"')
        alerts_resp = await client.get(
            f"{url}/security/events",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": limit},
        )
        alerts_resp.raise_for_status()
    items = alerts_resp.json().get("data", {}).get("affected_items", [])
    for item in items:
        await _ingest(_normalize_wazuh({"data": item}))
    return {"ingested": len(items)}


@app.post("/connectors/pull/elastic")
async def pull_elastic(size: int = 100):
    base = (await _secret_value("ELASTIC_SIEM_URL")) or ELASTIC_URL
    index = (await _secret_value("ELASTIC_SIEM_INDEX")) or ".siem-signals-*"
    api_key = await _secret_value("ELASTIC_SIEM_API_KEY")
    headers = {"Authorization": f"ApiKey {api_key}"} if api_key else {}
    body = {"size": size, "sort": [{"@timestamp": "desc"}], "query": {"match_all": {}}}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(f"{base}/{index}/_search", headers=headers, json=body)
        resp.raise_for_status()
    hits = resp.json().get("hits", {}).get("hits", [])
    for hit in hits:
        await _ingest(_normalize_elastic(hit))
    return {"ingested": len(hits)}


@app.post("/connectors/pull/splunk")
async def pull_splunk(count: int = 100):
    base = await _secret_value("SPLUNK_URL")
    token = await _secret_value("SPLUNK_TOKEN")
    search_name = await _secret_value("SPLUNK_SAVED_SEARCH")
    if not all([base, token, search_name]):
        raise HTTPException(status_code=400, detail="Splunk config missing")

    headers = {"Authorization": f"Bearer {token}"}
    verify_tls = os.getenv("SPLUNK_VERIFY_TLS", "true").lower() != "false"
    async with httpx.AsyncClient(verify=verify_tls, timeout=30) as client:
        job = await client.post(
            f"{base}/servicesNS/admin/search/saved/searches/{search_name}/dispatch",
            headers=headers,
            data={"output_mode": "json"},
        )
        job.raise_for_status()
        sid = job.json()["sid"]
        results = await client.get(
            f"{base}/services/search/jobs/{sid}/results",
            headers=headers,
            params={"output_mode": "json", "count": count},
        )
        results.raise_for_status()
    rows = results.json().get("results", [])
    for row in rows:
        await _ingest(_normalize_splunk(row))
    return {"ingested": len(rows)}


@app.post("/connectors/pull/sentinel")
async def pull_sentinel(limit: int = 100):
    tenant_id = await _secret_value("SENTINEL_TENANT_ID")
    client_id = await _secret_value("SENTINEL_CLIENT_ID")
    client_secret = await _secret_value("SENTINEL_CLIENT_SECRET")
    subscription_id = await _secret_value("SENTINEL_SUBSCRIPTION_ID")
    resource_group = await _secret_value("SENTINEL_RESOURCE_GROUP")
    workspace = await _secret_value("SENTINEL_WORKSPACE")

    if not all([tenant_id, client_id, client_secret, subscription_id, resource_group, workspace]):
        raise HTTPException(status_code=400, detail="Sentinel configuration missing")

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    incidents_url = (
        "https://management.azure.com/subscriptions/"
        f"{subscription_id}/resourceGroups/{resource_group}/providers/"
        "Microsoft.OperationalInsights/workspaces/"
        f"{workspace}/providers/Microsoft.SecurityInsights/incidents"
        "?api-version=2023-02-01-preview"
    )

    async with httpx.AsyncClient(timeout=45) as client:
        token_resp = await client.post(
            token_url,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
                "scope": "https://management.azure.com/.default",
            },
        )
        token_resp.raise_for_status()
        access_token = token_resp.json().get("access_token", "")

        incidents_resp = await client.get(
            incidents_url,
            headers={"Authorization": f"Bearer {access_token}"},
            params={"$top": limit},
        )
        incidents_resp.raise_for_status()
        items = incidents_resp.json().get("value", [])

    for item in items:
        await _ingest(_normalize_sentinel(item))
    return {"ingested": len(items)}


@app.post("/connectors/pull/opencti")
async def pull_opencti(limit: int = 100):
    ingested = await _pull_opencti(limit=limit)
    return {"ingested": ingested}


@app.post("/connectors/pull/abuseipdb")
async def pull_abuseipdb(limit: int = 100, confidence_minimum: int = 90):
    """Ingest AbuseIPDB blacklist into alerts (plan limits apply; often requires paid tier)."""
    ingested = await _pull_abuseipdb_blacklist(limit=limit, confidence_minimum=confidence_minimum)
    return {"ingested": ingested, "source": "abuseipdb"}
