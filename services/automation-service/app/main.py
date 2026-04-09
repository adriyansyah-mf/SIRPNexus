"""
Automation / SOAR-lite Service
- Kafka consumer on analyzers.results and cases.updated
- Playbook engine: stored playbooks with conditions + action steps
- Manual trigger: POST /automation/run-playbook/{id}
- Auto-trigger: severity + score thresholds
"""
import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import asyncpg
import httpx
from aiokafka import AIOKafkaConsumer
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

logger = logging.getLogger("sirp.automation")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Automation Service")
Instrumentator().instrument(app).expose(app)

INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")
SECRET_SERVICE_URL = os.getenv("SECRET_SERVICE_URL", "http://secret-service:8001")
KAFKA = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
POSTGRES_DSN = dict(
    host=os.getenv("POSTGRES_HOST", "postgres"),
    port=int(os.getenv("POSTGRES_PORT", "5432")),
    user=os.getenv("POSTGRES_USER", "sirp"),
    password=os.getenv("POSTGRES_PASSWORD", "sirp"),
    database=os.getenv("POSTGRES_DB", "sirp"),
)

consumer: AIOKafkaConsumer | None = None
db_pool: asyncpg.Pool | None = None

# ── Built-in playbooks (always available) ─────────────────────────────────────
BUILTIN_PLAYBOOKS: list[dict[str, Any]] = [
    {
        "id": "pb-block-malicious-ip",
        "name": "Block Malicious IP",
        "description": "Block IP on firewall + Wazuh active response when AbuseIPDB score ≥ 75",
        "trigger": "analyzer_result",
        "conditions": [
            {"field": "ioc_type", "op": "eq", "value": "ip"},
            {"field": "risk.final_score", "op": "gte", "value": 75},
        ],
        "actions": [
            {"type": "firewall_block", "params": {"target_field": "value"}},
            {"type": "wazuh_active_response", "params": {"command": "firewall-drop", "target_field": "value"}},
        ],
        "enabled": True,
    },
    {
        "id": "pb-isolate-host-hash",
        "name": "Isolate Host on Malicious Hash",
        "description": "Send EDR isolation request when hash is malicious and VT score ≥ 80",
        "trigger": "analyzer_result",
        "conditions": [
            {"field": "ioc_type", "op": "eq", "value": "hash"},
            {"field": "risk.final_score", "op": "gte", "value": 80},
        ],
        "actions": [
            {"type": "edr_isolate", "params": {"target_field": "value"}},
        ],
        "enabled": True,
    },
    {
        "id": "pb-notify-critical-case",
        "name": "Notify on Critical Case Created",
        "description": "Send webhook notification when a critical severity case is created",
        "trigger": "case_event",
        "conditions": [
            {"field": "event", "op": "eq", "value": "created"},
            {"field": "case.severity", "op": "eq", "value": "critical"},
        ],
        "actions": [
            {"type": "webhook_notify", "params": {"message_template": "CRITICAL case created: {case.title}"}},
        ],
        "enabled": True,
    },
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _nested_get(obj: dict, dotpath: str) -> Any:
    """Traverse nested dict with dot notation: 'risk.final_score' → obj['risk']['final_score']"""
    keys = dotpath.split(".")
    current: Any = obj
    for k in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(k)
    return current


def _eval_condition(event: dict, cond: dict) -> bool:
    val = _nested_get(event, cond["field"])
    op = cond["op"]
    target = cond["value"]
    if op == "eq":
        return val == target
    if op == "neq":
        return val != target
    if op == "gte":
        try:
            return float(val or 0) >= float(target)
        except (TypeError, ValueError):
            return False
    if op == "gt":
        try:
            return float(val or 0) > float(target)
        except (TypeError, ValueError):
            return False
    if op == "contains":
        return target in (val or "")
    return False


def _matches_playbook(playbook: dict, event: dict) -> bool:
    if not playbook.get("enabled", True):
        return False
    return all(_eval_condition(event, c) for c in playbook.get("conditions", []))


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


async def _post_action(url: str, token: str, payload: dict) -> bool:
    if not url:
        logger.debug("action skip: no URL configured")
        return False
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                url, json=payload,
                headers={"Authorization": f"Bearer {token}"} if token else {},
            )
            logger.info("action POST %s → %d", url, resp.status_code)
            return resp.status_code < 400
    except Exception as exc:
        logger.error("action POST %s failed: %s", url, exc)
        return False


async def _execute_action(action: dict, event: dict) -> dict[str, Any]:
    atype = action["type"]
    params = action.get("params", {})
    target_field = params.get("target_field", "value")
    ioc_value = event.get(target_field) or _nested_get(event, target_field)

    result: dict[str, Any] = {"type": atype, "ok": False, "at": _now()}

    if atype == "firewall_block":
        url = await _secret_value("FIREWALL_API_URL")
        token = await _secret_value("FIREWALL_API_TOKEN")
        result["ok"] = await _post_action(url, token, {"ip": ioc_value, "action": "block"})

    elif atype == "wazuh_active_response":
        url = await _secret_value("WAZUH_ACTIVE_RESPONSE_URL")
        token = await _secret_value("WAZUH_ACTIVE_RESPONSE_TOKEN")
        result["ok"] = await _post_action(url, token, {
            "command": params.get("command", "firewall-drop"),
            "srcip": ioc_value,
        })

    elif atype == "edr_isolate":
        url = await _secret_value("EDR_API_URL")
        token = await _secret_value("EDR_API_TOKEN")
        result["ok"] = await _post_action(url, token, {"indicator": ioc_value, "action": "isolate_host"})

    elif atype == "webhook_notify":
        slack_url = await _secret_value("SLACK_WEBHOOK_URL")
        template = params.get("message_template", "Automation triggered: {event}")
        try:
            msg = template.format(**{k: str(v) for k, v in event.items() if isinstance(v, (str, int, float))})
        except (KeyError, ValueError):
            msg = template
        result["ok"] = await _post_action(slack_url, "", {"text": msg})

    else:
        logger.warning("unknown action type: %s", atype)

    return result


async def _run_matching_playbooks(trigger: str, event: dict) -> list[dict[str, Any]]:
    """Run all enabled playbooks whose trigger + conditions match this event."""
    triggered = []
    playbooks = await _list_all_playbooks()
    for pb in playbooks:
        if pb.get("trigger") != trigger:
            continue
        if not _matches_playbook(pb, event):
            continue
        logger.info("playbook %s (%s) triggered by %s", pb["id"], pb["name"], trigger)
        action_results = []
        for action in pb.get("actions", []):
            res = await _execute_action(action, event)
            action_results.append(res)
        if db_pool:
            await db_pool.execute(
                "INSERT INTO automation_runs(id, playbook_id, trigger, event_summary, action_results, ran_at) "
                "VALUES($1,$2,$3,$4::jsonb,$5::jsonb, now())",
                str(uuid.uuid4()),
                pb["id"],
                trigger,
                json.dumps({k: v for k, v in event.items() if k not in {"raw", "analysis"}}, default=str),
                json.dumps(action_results),
            )
        triggered.append({"playbook": pb["id"], "name": pb["name"], "actions": action_results})
    return triggered


async def _list_all_playbooks() -> list[dict[str, Any]]:
    """Return built-ins + custom playbooks from DB."""
    custom: list[dict[str, Any]] = []
    if db_pool:
        rows = await db_pool.fetch("SELECT payload FROM playbooks ORDER BY created_at DESC")
        for row in rows:
            payload = row["payload"]
            if isinstance(payload, dict):
                custom.append(payload)
            elif isinstance(payload, str):
                try:
                    custom.append(json.loads(payload))
                except Exception:
                    pass
    return BUILTIN_PLAYBOOKS + custom


# ── Kafka consumer ─────────────────────────────────────────────────────────────
async def kafka_worker():
    assert consumer
    logger.info("automation kafka worker started")
    async for msg in consumer:
        try:
            data = json.loads(msg.value.decode())
            topic = msg.topic

            if topic == "analyzers.results":
                # Flatten result structure for condition matching
                event = {
                    "ioc_type": data.get("type"),
                    "value": data.get("value"),
                    "alert_id": data.get("alert_id"),
                    "risk": data.get("result", {}).get("risk", {}),
                }
                await _run_matching_playbooks("analyzer_result", event)

            elif topic == "cases.updated":
                event = data  # already flat: {event, case_id, ...}
                await _run_matching_playbooks("case_event", event)

        except json.JSONDecodeError as exc:
            logger.error("automation worker: malformed JSON: %s", exc)
        except Exception as exc:
            logger.exception("automation worker error: %s", exc)


# ── App lifecycle ──────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global consumer, db_pool
    consumer = AIOKafkaConsumer(
        "analyzers.results",
        "cases.updated",
        bootstrap_servers=KAFKA,
        group_id="automation-service",
    )
    await consumer.start()
    db_pool = await asyncpg.create_pool(**POSTGRES_DSN, min_size=1, max_size=3)
    await db_pool.execute(
        "CREATE TABLE IF NOT EXISTS playbooks ("
        "id TEXT PRIMARY KEY, payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
    )
    await db_pool.execute(
        "CREATE TABLE IF NOT EXISTS automation_runs ("
        "id TEXT PRIMARY KEY, playbook_id TEXT, trigger TEXT, event_summary JSONB, "
        "action_results JSONB, ran_at TIMESTAMPTZ NOT NULL DEFAULT now())"
    )
    asyncio.create_task(kafka_worker())
    logger.info("automation service ready")


@app.on_event("shutdown")
async def shutdown():
    if consumer:
        await consumer.stop()
    if db_pool:
        await db_pool.close()


# ── Auth middleware ────────────────────────────────────────────────────────────
@app.middleware("http")
async def enforce_internal_token(request: Request, call_next):
    if request.url.path in {"/health", "/metrics"}:
        return await call_next(request)
    if INTERNAL_SERVICE_TOKEN and request.headers.get("x-internal-token") != INTERNAL_SERVICE_TOKEN:
        return JSONResponse(status_code=401, content={"detail": "Invalid internal service token"})
    return await call_next(request)


@app.get("/health")
async def health():
    return {"status": "ok"}


# ── Playbook CRUD ──────────────────────────────────────────────────────────────
@app.get("/automation/playbooks")
async def list_playbooks():
    return await _list_all_playbooks()


@app.get("/automation/playbooks/{pb_id}")
async def get_playbook(pb_id: str):
    for pb in await _list_all_playbooks():
        if pb["id"] == pb_id:
            return pb
    raise HTTPException(status_code=404, detail="Playbook not found")


@app.post("/automation/playbooks")
async def create_playbook(body: dict[str, Any]):
    if not body.get("name") or not body.get("trigger"):
        raise HTTPException(status_code=400, detail="name and trigger required")
    if body.get("trigger") not in {"analyzer_result", "case_event", "manual"}:
        raise HTTPException(status_code=400, detail="trigger must be analyzer_result | case_event | manual")
    pb_id = body.get("id") or f"pb-{uuid.uuid4().hex[:8]}"
    pb = {
        "id": pb_id,
        "name": body["name"],
        "description": body.get("description", ""),
        "trigger": body["trigger"],
        "conditions": body.get("conditions", []),
        "actions": body.get("actions", []),
        "enabled": body.get("enabled", True),
        "created_at": _now(),
    }
    if db_pool:
        try:
            await db_pool.execute(
                "INSERT INTO playbooks(id, payload) VALUES($1, $2::jsonb)",
                pb_id, json.dumps(pb),
            )
        except asyncpg.UniqueViolationError:
            raise HTTPException(status_code=409, detail=f"Playbook '{pb_id}' already exists")
    return pb


@app.put("/automation/playbooks/{pb_id}/toggle")
async def toggle_playbook(pb_id: str, body: dict[str, bool]):
    # Only custom DB playbooks can be toggled
    if not db_pool:
        raise HTTPException(status_code=503, detail="DB not available")
    row = await db_pool.fetchrow("SELECT payload FROM playbooks WHERE id=$1", pb_id)
    if not row:
        raise HTTPException(status_code=404, detail="Playbook not found in custom store")
    pb = dict(row["payload"])
    pb["enabled"] = body.get("enabled", not pb.get("enabled", True))
    await db_pool.execute("UPDATE playbooks SET payload=$1::jsonb WHERE id=$2", json.dumps(pb), pb_id)
    return pb


@app.delete("/automation/playbooks/{pb_id}")
async def delete_playbook(pb_id: str):
    if not db_pool:
        raise HTTPException(status_code=503, detail="DB not available")
    result = await db_pool.execute("DELETE FROM playbooks WHERE id=$1", pb_id)
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Playbook not found in custom store")
    return {"status": "deleted", "id": pb_id}


# ── Manual trigger ─────────────────────────────────────────────────────────────
@app.post("/automation/playbooks/{pb_id}/run")
async def run_playbook(pb_id: str, event: dict[str, Any]):
    all_pbs = await _list_all_playbooks()
    pb = next((p for p in all_pbs if p["id"] == pb_id), None)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    action_results = []
    for action in pb.get("actions", []):
        res = await _execute_action(action, event)
        action_results.append(res)
    return {"playbook": pb_id, "actions": action_results}


# ── Automation runs log ────────────────────────────────────────────────────────
@app.get("/automation/runs")
async def list_runs(limit: int = 50):
    if not db_pool:
        return []
    rows = await db_pool.fetch(
        "SELECT id, playbook_id, trigger, event_summary, action_results, ran_at "
        "FROM automation_runs ORDER BY ran_at DESC LIMIT $1",
        limit,
    )
    return [
        {
            "id": r["id"],
            "playbook_id": r["playbook_id"],
            "trigger": r["trigger"],
            "event_summary": r["event_summary"],
            "action_results": r["action_results"],
            "ran_at": r["ran_at"].isoformat(),
        }
        for r in rows
    ]


# ── Legacy single-run endpoint (backward compat) ──────────────────────────────
@app.post("/automation/run-once")
async def run_once(event: dict[str, Any]):
    results = await _run_matching_playbooks("analyzer_result", {
        "ioc_type": event.get("job", {}).get("type"),
        "value": event.get("job", {}).get("value"),
        "risk": event.get("result", {}).get("risk", {}),
    })
    return {"status": "processed", "triggered": results}
