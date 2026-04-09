import asyncio
import hashlib
import ipaddress
import json
import os
import re
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

producer: AIOKafkaProducer | None = None
redis_client: Redis | None = None
es: AsyncElasticsearch | None = None
db_pool: asyncpg.Pool | None = None
opencti_sync_task = None
ALERTS: list[dict[str, Any]] = []

KAFKA = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
ELASTIC_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
INGEST_ALLOWLIST = [v.strip() for v in os.getenv("INGEST_ALLOWLIST", "0.0.0.0/0").split(",")]
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")
SECRET_SERVICE_URL = os.getenv("SECRET_SERVICE_URL", "http://secret-service:8001")


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
    base_url = (await _secret_value("OPENCTI_URL")).rstrip("/")
    token = await _secret_value("OPENCTI_TOKEN")
    if not base_url or not token:
        raise HTTPException(status_code=400, detail="OpenCTI configuration missing")

    query = """
    query ListObservables($first: Int!) {
      stixCyberObservables(first: $first, orderBy: updated_at, orderMode: desc) {
        edges {
          node {
            id
            entity_type
            observable_value
            x_opencti_description
            confidence
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

    async with httpx.AsyncClient(timeout=45) as client:
        resp = await client.post(
            f"{base_url}/graphql",
            json={"query": query, "variables": {"first": limit}},
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        resp.raise_for_status()
        payload = resp.json()

    edges = payload.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
    ingested = 0
    for edge in edges:
        node = edge.get("node", {})
        labels = node.get("objectLabel", {}).get("edges", [])
        node["objectLabel"] = [entry.get("node", {}) for entry in labels]
        out = await _ingest(_normalize_opencti(node))
        if out.get("status") != "duplicate":
            ingested += 1
    return ingested


async def _opencti_sync_loop():
    interval = int(os.getenv("OPENCTI_AUTO_SYNC_INTERVAL_SECONDS", "300"))
    limit = int(os.getenv("OPENCTI_QUERY_LIMIT", "100"))
    while True:
        try:
            await _pull_opencti(limit=limit)
        except Exception:
            # Keep periodic sync alive; temporary OpenCTI errors should not stop service.
            pass
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
    return alert


@app.on_event("startup")
async def startup():
    global producer, redis_client, es, db_pool, opencti_sync_task
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA)
    await producer.start()
    redis_client = Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))
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
    if os.getenv("OPENCTI_AUTO_SYNC_ENABLED", "false").lower() == "true":
        opencti_sync_task = asyncio.create_task(_opencti_sync_loop())


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


@app.middleware("http")
async def enforce_internal_token(request: Request, call_next):
    if request.url.path in {"/health", "/metrics"} or request.url.path.startswith("/alerts/webhook/"):
        return await call_next(request)
    if INTERNAL_SERVICE_TOKEN and request.headers.get("x-internal-token") != INTERNAL_SERVICE_TOKEN:
        return JSONResponse(status_code=401, content={"detail": "Invalid internal service token"})
    return await call_next(request)


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


@app.get("/alerts")
async def list_alerts():
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
    return ALERTS


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


_ANALYZER_IOC_TYPES = frozenset({"ip", "domain", "url", "hash", "email"})


def _normalize_ioc_for_analyzer(raw_type: str) -> str | None:
    t = (raw_type or "").strip().lower()
    if t == "hostname":
        t = "domain"
    return t if t in _ANALYZER_IOC_TYPES else None


@app.post("/alerts/{alert_id}/run-analyzers")
async def run_analyzers(alert_id: str):
    alert = await _get_alert_or_404(alert_id)
    observables = alert.get("observables", [])
    queued = 0
    for observable in observables:
        raw_t = str(observable.get("type") or "").lower()
        ioc_type = _normalize_ioc_for_analyzer(raw_t)
        if not ioc_type:
            continue
        v = observable.get("value")
        if v is None or str(v).strip() == "":
            continue
        await _publish(
            "analyzers.jobs",
            {
                "alert_id": alert_id,
                "severity": alert.get("severity"),
                "type": ioc_type,
                "value": str(v).strip()[:800],
            },
        )
        queued += 1
    return {
        "status": "queued",
        "observable_count": len(observables),
        "queued_count": queued,
    }


@app.post("/alerts/{alert_id}/observables/analyze")
async def analyze_single_observable(alert_id: str, body: dict[str, Any]):
    """Queue one IOC for the analyzer service (Threat Intel), keyed by alert_id for result storage."""
    alert = await _get_alert_or_404(alert_id)
    raw_type = str(body.get("type") or "").strip().lower()
    ioc_type = _normalize_ioc_for_analyzer(raw_type)
    if not ioc_type:
        raise HTTPException(
            status_code=400,
            detail=f"IOC type '{raw_type or 'missing'}' is not supported for Threat Intel analyzers",
        )
    val = body.get("value")
    if val is None or str(val).strip() == "":
        raise HTTPException(status_code=400, detail="value required")
    v = str(val).strip()[:800]
    await _publish(
        "analyzers.jobs",
        {
            "alert_id": alert_id,
            "severity": alert.get("severity"),
            "type": ioc_type,
            "value": v,
        },
    )
    return {"status": "queued", "type": ioc_type, "value": v[:200]}


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
