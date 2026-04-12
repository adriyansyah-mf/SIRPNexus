import json
import os
import re
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import asyncpg
import httpx
from aiokafka import AIOKafkaProducer
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI(title="Case Service")
Instrumentator().instrument(app).expose(app)
producer: AIOKafkaProducer | None = None
db_pool: asyncpg.Pool | None = None
KAFKA = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
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
API_GATEWAY_URL = os.getenv("API_GATEWAY_URL", "http://api-gateway:8000").rstrip("/")
ALERT_SERVICE_URL = os.getenv("ALERT_SERVICE_URL", "http://alert-service:8001").rstrip("/")
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "")
FERNET = Fernet(DATA_ENCRYPTION_KEY.encode()) if DATA_ENCRYPTION_KEY else None

EVIDENCE_DIR = Path(os.getenv("CASE_EVIDENCE_DIR", "/tmp/sirp-case-evidence")).resolve()
MAX_EVIDENCE_BYTES = int(os.getenv("CASE_EVIDENCE_MAX_BYTES", str(25 * 1024 * 1024)))
_UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", re.I)

CASES: dict[str, dict[str, Any]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encrypt_text(value: str | None) -> str | None:
    if not value or not FERNET:
        return value
    return FERNET.encrypt(value.encode()).decode()


def _decrypt_text(value: str | None) -> str | None:
    if not value or not FERNET:
        return value
    try:
        return FERNET.decrypt(value.encode()).decode()
    except InvalidToken:
        return value


def _encrypt_case_payload(case: dict[str, Any]) -> dict[str, Any]:
    doc = deepcopy(case)
    doc["description"] = _encrypt_text(doc.get("description"))
    for comment in doc.get("comments", []):
        comment["text"] = _encrypt_text(comment.get("text"))
    return doc


def _decrypt_case_payload(case: dict[str, Any]) -> dict[str, Any]:
    doc = deepcopy(case)
    doc["description"] = _decrypt_text(doc.get("description"))
    for comment in doc.get("comments", []):
        comment["text"] = _decrypt_text(comment.get("text"))
    return doc


async def _emit(event: str, payload: dict[str, Any]):
    assert producer
    await producer.send_and_wait("cases.updated", json.dumps({"event": event, **payload}, default=str).encode())
    await _post_emit_gateway_hooks(event, payload)


async def _notify_gateway_watchers(event: str, case_id: str, summary: str, actor: str) -> None:
    if not INTERNAL_SERVICE_TOKEN or not API_GATEWAY_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            await client.post(
                f"{API_GATEWAY_URL}/soc/internal/watchers/notify",
                headers={"x-internal-token": INTERNAL_SERVICE_TOKEN},
                json={"case_id": case_id, "event": event, "summary": summary[:500], "actor": actor},
            )
    except Exception:
        pass


async def _post_emit_gateway_hooks(event: str, payload: dict[str, Any]) -> None:
    if event not in {
        "comment_added",
        "status_updated",
        "task_added",
        "evidence_uploaded",
        "case_linked",
        "assigned",
        "created",
    }:
        return
    cid = payload.get("case_id")
    if not cid and isinstance(payload.get("case"), dict):
        cid = payload["case"].get("id")
    if not cid:
        return
    actor = str(payload.get("actor", "") or payload.get("assignment", {}).get("assigned_by", "") or "")
    summary = event
    if event == "comment_added" and isinstance(payload.get("comment"), dict):
        summary = str(payload["comment"].get("text", ""))[:200] or event
    elif event == "status_updated":
        summary = f"status → {payload.get('status', '')}"
    elif event == "task_added" and isinstance(payload.get("task"), dict):
        summary = f"task: {payload['task'].get('title', '')}"
    elif event == "evidence_uploaded":
        summary = f"evidence: {payload.get('filename', '')}"
    elif event == "case_linked":
        summary = f"linked → {payload.get('target_case_id', '')}"
    elif event == "assigned":
        summary = f"assigned → {payload.get('assignment', {}).get('assigned_to', '')}"
    elif event == "created":
        summary = "new case"
    await _notify_gateway_watchers(event, str(cid), summary, actor)


async def _notify_gateway_mentions(
    case_id: str,
    comment_id: str,
    author: str,
    mentioned_users: list[str],
    excerpt: str,
    case_title: str,
) -> None:
    if not mentioned_users or not INTERNAL_SERVICE_TOKEN or not API_GATEWAY_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"{API_GATEWAY_URL}/soc/internal/mentions/ingest",
                headers={"x-internal-token": INTERNAL_SERVICE_TOKEN},
                json={
                    "case_id": case_id,
                    "comment_id": comment_id,
                    "author": author,
                    "mentioned_users": mentioned_users,
                    "excerpt": excerpt[:800],
                    "case_title": case_title[:300],
                },
            )
    except Exception:
        pass


def _validate_case_id(case_id: str) -> str:
    if not _UUID_RE.match(case_id.strip()):
        raise HTTPException(status_code=400, detail="Invalid case id")
    return case_id.strip()


def _safe_filename(name: str) -> str:
    base = Path(name or "file").name
    base = re.sub(r"[^a-zA-Z0-9._-]", "_", base).strip("._") or "file"
    return base[:200]


def _evidence_base_dir(case_id: str) -> Path:
    cid = _validate_case_id(case_id)
    return (EVIDENCE_DIR / cid).resolve()


def _resolved_evidence_path(case_id: str, stored_name: str) -> Path:
    base = _evidence_base_dir(case_id)
    path = (base / stored_name).resolve()
    if not str(path).startswith(str(base)) or path == base:
        raise HTTPException(status_code=400, detail="Invalid evidence path")
    return path


async def _persist_case(case_id: str, case: dict[str, Any]):
    if not db_pool:
        return
    await db_pool.execute(
        "INSERT INTO cases(id, payload, created_at) VALUES($1, $2::jsonb, now()) "
        "ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload",
        case_id,
        json.dumps(_encrypt_case_payload(case)),
    )


MAX_CASE_AUDIT_EVENTS = 500


def _append_case_audit(case: dict[str, Any], actor: str, action: str, detail: dict[str, Any] | None = None) -> None:
    """Append-only SOC audit trail on the case document (field-level / action context)."""
    case.setdefault("audit_events", [])
    case["audit_events"].append(
        {"at": _now(), "actor": actor or "system", "action": action, "detail": detail or {}}
    )
    case["audit_events"] = case["audit_events"][-MAX_CASE_AUDIT_EVENTS:]


class CaseFromAlert(BaseModel):
    model_config = ConfigDict(extra="ignore")

    alert_id: str
    title: str = "Untitled"
    description: str = ""
    observables: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    severity: str = "medium"
    owner: str = ""

    @field_validator("alert_id", mode="before")
    @classmethod
    def alert_id_str(cls, v: Any) -> str:
        if v is None:
            return ""
        return str(v)

    @field_validator("title", mode="before")
    @classmethod
    def title_ok(cls, v: Any) -> str:
        if v is None or (isinstance(v, str) and not str(v).strip()):
            return "Untitled"
        return str(v).strip()[:500]

    @field_validator("description", mode="before")
    @classmethod
    def desc_ok(cls, v: Any) -> str:
        if v is None:
            return ""
        return str(v)[:16000]

    @field_validator("owner", mode="before")
    @classmethod
    def owner_ok(cls, v: Any) -> str:
        return "" if v is None else str(v)[:200]

    @field_validator("severity", mode="before")
    @classmethod
    def sev_ok(cls, v: Any) -> str:
        s = str(v or "medium").lower()
        return s if s in {"low", "medium", "high", "critical"} else "medium"

    @field_validator("observables", mode="before")
    @classmethod
    def obs_ok(cls, v: Any) -> list[dict[str, Any]]:
        if not isinstance(v, list):
            return []
        out: list[dict[str, Any]] = []
        for item in v:
            if not isinstance(item, dict):
                continue
            val = item.get("value")
            if val is None or val == "":
                continue
            out.append({"type": str(item.get("type") or "other"), "value": str(val)[:800]})
        return out

    @field_validator("tags", mode="before")
    @classmethod
    def tags_ok(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        return [str(x) for x in v if x is not None][:64]


class CaseCreate(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"
    owner: str = ""
    tags: list[str] = []

    @field_validator("title", mode="before")
    @classmethod
    def title_ok(cls, v: Any) -> str:
        if v is None or (isinstance(v, str) and not str(v).strip()):
            raise ValueError("title is required")
        return str(v).strip()[:500]

    @field_validator("description", mode="before")
    @classmethod
    def desc_ok(cls, v: Any) -> str:
        if v is None:
            return ""
        return str(v)[:16000]

    @field_validator("owner", mode="before")
    @classmethod
    def owner_ok(cls, v: Any) -> str:
        return "" if v is None else str(v)[:200]

    @field_validator("severity", mode="before")
    @classmethod
    def sev_ok(cls, v: Any) -> str:
        s = str(v or "medium").lower()
        return s if s in {"low", "medium", "high", "critical"} else "medium"

    @field_validator("tags", mode="before")
    @classmethod
    def tags_ok(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        return [str(x) for x in v if x is not None][:64]


class Assignment(BaseModel):
    assigned_to: str
    assigned_by: str


class StatusBody(BaseModel):
    status: str = Field(pattern="^(open|in-progress|resolved|closed)$")
    actor: str


class CommentBody(BaseModel):
    author: str
    text: str


class TaskBody(BaseModel):
    title: str
    assigned_to: str = ""
    status: str = "open"


class TaskStatusBody(BaseModel):
    status: str = Field(pattern="^(open|in-progress|done)$")
    actor: str = ""


class CaseLinkBody(BaseModel):
    target_case_id: str
    actor: str = ""

    @field_validator("target_case_id", mode="before")
    @classmethod
    def target_uuid(cls, v: Any) -> str:
        s = str(v or "").strip()
        if not _UUID_RE.match(s):
            raise ValueError("invalid target case id")
        return s


class SocMetaPatch(BaseModel):
    model_config = ConfigDict(extra="ignore")

    incident_category: str | None = None
    legal_hold: bool | None = None
    shift_handover_notes: str | None = None
    actor: str = "analyst"

    @field_validator("incident_category", mode="before")
    @classmethod
    def incident_cat_ok(cls, v: Any) -> str | None:
        if v is None:
            return None
        s = str(v).strip()[:120]
        return s or None

    @field_validator("shift_handover_notes", mode="before")
    @classmethod
    def handover_ok(cls, v: Any) -> str | None:
        if v is None:
            return None
        return str(v)[:8000]

    @field_validator("actor", mode="before")
    @classmethod
    def actor_ok(cls, v: Any) -> str:
        return str(v or "analyst").strip()[:200] or "analyst"


@app.on_event("startup")
async def startup():
    global producer, db_pool
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA)
    await producer.start()
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
        "CREATE TABLE IF NOT EXISTS cases ("
        "id TEXT PRIMARY KEY, payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
    )
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


@app.on_event("shutdown")
async def shutdown():
    if producer:
        await producer.stop()
    if db_pool:
        await db_pool.close()


@app.middleware("http")
async def enforce_internal_token(request: Request, call_next):
    if request.url.path in {"/health", "/metrics"}:
        return await call_next(request)
    if not INTERNAL_SERVICE_TOKEN.strip():
        if ALLOW_INSECURE_NO_INTERNAL_TOKEN:
            return await call_next(request)
        return JSONResponse(status_code=503, content={"detail": "INTERNAL_SERVICE_TOKEN is not configured"})
    if request.headers.get("x-internal-token") != INTERNAL_SERVICE_TOKEN:
        return JSONResponse(status_code=401, content={"detail": "Invalid internal service token"})
    return await call_next(request)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/cases")
async def list_cases():
    if db_pool:
        rows = await db_pool.fetch("SELECT payload FROM cases ORDER BY created_at DESC LIMIT 1000")
        out: list[dict[str, Any]] = []
        for r in rows:
            p = r["payload"]
            if isinstance(p, str):
                try:
                    p = json.loads(p)
                except Exception:
                    continue
            if not isinstance(p, dict):
                continue
            out.append(_decrypt_case_payload(dict(p)))
        return out
    return list(CASES.values())


async def _all_cases_decrypted() -> list[dict[str, Any]]:
    if db_pool:
        rows = await db_pool.fetch("SELECT payload FROM cases ORDER BY created_at DESC LIMIT 500")
        out: list[dict[str, Any]] = []
        for r in rows:
            p = r["payload"]
            if isinstance(p, str):
                try:
                    p = json.loads(p)
                except Exception:
                    continue
            if isinstance(p, dict):
                out.append(_decrypt_case_payload(dict(p)))
        return out
    return [dict(_decrypt_case_payload(c)) for c in CASES.values()]


def _obs_tuples(c: dict[str, Any]) -> set[tuple[str, str]]:
    s: set[tuple[str, str]] = set()
    for o in c.get("observables") or []:
        if isinstance(o, dict) and o.get("value"):
            s.add((str(o.get("type", "other")), str(o["value"])[:500]))
    return s


def _tags_lower(c: dict[str, Any]) -> set[str]:
    return {str(t).lower() for t in (c.get("tags") or []) if t}


def _within_case_window(iso_ts: str | None, days: int) -> bool:
    if not iso_ts or days <= 0:
        return True
    try:
        t = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return t >= datetime.now(timezone.utc) - timedelta(days=days)
    except Exception:
        return True


async def _fetch_alert_payload(alert_id: str) -> dict[str, Any] | None:
    if not alert_id.strip():
        return None
    headers: dict[str, str] = {}
    if INTERNAL_SERVICE_TOKEN:
        headers["x-internal-token"] = INTERNAL_SERVICE_TOKEN
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{ALERT_SERVICE_URL}/alerts/{alert_id.strip()}", headers=headers)
            if r.status_code != 200:
                return None
            body = r.json()
            return body if isinstance(body, dict) else None
    except Exception:
        return None


def _row_payload(row: asyncpg.Record | None) -> dict[str, Any] | None:
    if not row:
        return None
    p = row["payload"]
    if isinstance(p, str):
        try:
            p = json.loads(p)
        except Exception:
            return None
    if not isinstance(p, dict):
        return None
    return _decrypt_case_payload(dict(p))


@app.get("/cases/{case_id}")
async def get_case(case_id: str):
    case = CASES.get(case_id)
    if not case and db_pool:
        row = await db_pool.fetchrow("SELECT payload FROM cases WHERE id = $1", case_id)
        case = _row_payload(row)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case.setdefault("linked_case_ids", [])
    case.setdefault("evidence", [])
    case.setdefault("audit_events", [])
    case.setdefault("incident_category", None)
    case.setdefault("legal_hold", False)
    case.setdefault("shift_handover_notes", "")
    return case


@app.get("/cases/{case_id}/export")
async def export_case_bundle(case_id: str):
    """Full case JSON for auditors / handover (includes audit_events, evidence metadata)."""
    case = await get_case(case_id)
    return {
        "export_version": 2,
        "exported_at": _now(),
        "case": case,
    }


def _build_case(case_id: str, title: str, description: str, severity: str = "medium",
                owner: str = "", alert_id: str = "", observables: list | None = None,
                tags: list | None = None) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "id": case_id,
        "alert_id": alert_id,
        "title": title,
        "description": description,
        "severity": severity,
        "owner": owner,
        "observables": observables or [],
        "tags": tags or [],
        "status": "open",
        "assigned_to": None,
        "assigned_by": None,
        "assigned_at": None,
        "timeline": [{"event": "case_created", "at": _now()}],
        "comments": [],
        "tasks": [],
        "sla": {
            "response_due": (now + timedelta(minutes=30)).isoformat(),
            "resolution_due": (now + timedelta(hours=8)).isoformat(),
            "breached": False,
        },
        "created_at": _now(),
        "updated_at": _now(),
        "evidence": [],
        "linked_case_ids": [],
        "audit_events": [],
        "incident_category": None,
        "legal_hold": False,
        "shift_handover_notes": "",
    }


@app.post("/cases")
async def create_case(body: CaseCreate):
    """Create a case without linking an alert (manual / proactive SOC case)."""
    case_id = str(uuid.uuid4())
    case = _build_case(case_id, body.title, body.description, body.severity, body.owner, tags=body.tags)
    case["timeline"] = [{"event": "case_created_manual", "at": _now()}]
    _append_case_audit(case, body.owner or "system", "case_created", {"source": "manual", "title": body.title})
    CASES[case_id] = case
    await _persist_case(case_id, case)
    await _emit("created", {"case": case})
    return case


@app.post("/cases/from-alert")
async def create_from_alert(body: CaseFromAlert):
    case_id = str(uuid.uuid4())
    case = _build_case(
        case_id, body.title, body.description, body.severity, body.owner,
        alert_id=body.alert_id, observables=body.observables, tags=body.tags,
    )
    case["timeline"][0]["event"] = "case_created_from_alert"
    _append_case_audit(
        case,
        body.owner or "system",
        "case_created",
        {"source": "alert", "alert_id": body.alert_id, "title": body.title},
    )
    CASES[case_id] = case
    await _persist_case(case_id, case)
    await _emit("created", {"case": case})
    return case


@app.post("/cases/{case_id}/assign")
async def assign_case(case_id: str, body: Assignment):
    case = await get_case(case_id)
    prev_to = case.get("assigned_to")
    case["assigned_to"] = body.assigned_to
    case["assigned_by"] = body.assigned_by
    case["assigned_at"] = _now()
    case["updated_at"] = _now()
    case["timeline"].append({"event": "assigned", "at": _now(), **body.model_dump()})
    _append_case_audit(
        case,
        body.assigned_by,
        "assigned",
        {"assigned_to": body.assigned_to, "previous_assigned_to": prev_to},
    )
    CASES[case_id] = case
    await _persist_case(case_id, case)
    await _emit(
        "assigned",
        {"case_id": case_id, "assignment": body.model_dump(), "actor": body.assigned_by},
    )
    return case


@app.post("/cases/{case_id}/status")
async def update_status(case_id: str, body: StatusBody):
    case = await get_case(case_id)
    if case["assigned_to"] and body.actor not in {case["assigned_to"], "admin"}:
        raise HTTPException(status_code=403, detail="Only owner or admin can update")
    prev_status = case.get("status")
    case["status"] = body.status
    case["updated_at"] = _now()
    case["timeline"].append({"event": "status_changed", "at": _now(), **body.model_dump()})
    _append_case_audit(
        case,
        body.actor,
        "status_changed",
        {"status": body.status, "previous_status": prev_status},
    )
    CASES[case_id] = case
    await _persist_case(case_id, case)
    await _emit("status_updated", {"case_id": case_id, "status": body.status, "actor": body.actor})
    return case


@app.post("/cases/{case_id}/comments")
async def add_comment(case_id: str, body: CommentBody):
    case = await get_case(case_id)
    comment = {
        "id": str(uuid.uuid4()),
        "author": body.author,
        "text": body.text,
        "at": _now(),
        "edited": False,
    }
    case["comments"].append(comment)
    case["updated_at"] = _now()
    case["timeline"].append({"event": "comment_added", "at": _now(), "comment_id": comment["id"]})
    _append_case_audit(case, body.author, "comment_added", {"comment_id": comment["id"]})
    CASES[case_id] = case
    await _persist_case(case_id, case)
    text_plain = str(comment.get("text") or "")
    mention_users = sorted(set(re.findall(r"@([\w.\-]{2,80})", text_plain)))
    if mention_users:
        await _notify_gateway_mentions(
            case_id,
            comment["id"],
            body.author,
            mention_users,
            text_plain,
            str(case.get("title") or ""),
        )
    await _emit("comment_added", {"case_id": case_id, "comment": comment, "actor": body.author})
    return comment


@app.put("/cases/{case_id}/comments/{comment_id}")
async def edit_comment(case_id: str, comment_id: str, body: CommentBody):
    case = await get_case(case_id)
    for comment in case.get("comments", []):
        if comment["id"] == comment_id:
            comment["text"] = body.text
            comment["edited"] = True
            comment["edited_at"] = _now()
            case["updated_at"] = _now()
            _append_case_audit(case, body.author, "comment_edited", {"comment_id": comment_id})
            CASES[case_id] = case
            await _persist_case(case_id, case)
            return comment
    raise HTTPException(status_code=404, detail="Comment not found")


@app.delete("/cases/{case_id}/comments/{comment_id}")
async def delete_comment(case_id: str, comment_id: str):
    case = await get_case(case_id)
    before = len(case.get("comments", []))
    case["comments"] = [c for c in case.get("comments", []) if c["id"] != comment_id]
    if len(case["comments"]) == before:
        raise HTTPException(status_code=404, detail="Comment not found")
    case["updated_at"] = _now()
    _append_case_audit(case, "system", "comment_deleted", {"comment_id": comment_id})
    CASES[case_id] = case
    await _persist_case(case_id, case)
    return {"status": "deleted", "comment_id": comment_id}


@app.post("/cases/{case_id}/tasks")
async def add_task(case_id: str, body: TaskBody):
    case = await get_case(case_id)
    task = {
        "id": str(uuid.uuid4()),
        "title": body.title,
        "assigned_to": body.assigned_to or None,
        "status": "open",
        "created_at": _now(),
    }
    case["tasks"].append(task)
    case["updated_at"] = _now()
    case["timeline"].append({"event": "task_added", "at": _now(), "task_id": task["id"]})
    _append_case_audit(case, "system", "task_added", {"task_id": task["id"], "title": task["title"]})
    CASES[case_id] = case
    await _persist_case(case_id, case)
    await _emit("task_added", {"case_id": case_id, "task": task})
    return task


@app.put("/cases/{case_id}/tasks/{task_id}")
async def update_task(case_id: str, task_id: str, body: TaskStatusBody):
    case = await get_case(case_id)
    for task in case.get("tasks", []):
        if task["id"] == task_id:
            prev = task.get("status")
            task["status"] = body.status
            task["updated_at"] = _now()
            case["updated_at"] = _now()
            case["timeline"].append({"event": "task_updated", "at": _now(), "task_id": task_id, "status": body.status})
            _append_case_audit(
                case,
                body.actor or "system",
                "task_status_changed",
                {"task_id": task_id, "status": body.status, "previous_status": prev},
            )
            CASES[case_id] = case
            await _persist_case(case_id, case)
            return task
    raise HTTPException(status_code=404, detail="Task not found")


@app.delete("/cases/{case_id}/tasks/{task_id}")
async def delete_task(case_id: str, task_id: str):
    case = await get_case(case_id)
    before = len(case.get("tasks", []))
    case["tasks"] = [t for t in case.get("tasks", []) if t["id"] != task_id]
    if len(case["tasks"]) == before:
        raise HTTPException(status_code=404, detail="Task not found")
    case["updated_at"] = _now()
    _append_case_audit(case, "system", "task_deleted", {"task_id": task_id})
    CASES[case_id] = case
    await _persist_case(case_id, case)
    return {"status": "deleted", "task_id": task_id}


@app.patch("/cases/{case_id}/soc-meta")
async def patch_soc_meta(case_id: str, body: SocMetaPatch):
    """SOC operational fields: incident taxonomy, legal hold, shift handover notes."""
    _validate_case_id(case_id)
    case = await get_case(case_id)
    changes: dict[str, Any] = {}
    if body.incident_category is not None:
        changes["incident_category"] = {"from": case.get("incident_category"), "to": body.incident_category}
        case["incident_category"] = body.incident_category
    if body.legal_hold is not None:
        changes["legal_hold"] = {"from": case.get("legal_hold"), "to": body.legal_hold}
        case["legal_hold"] = bool(body.legal_hold)
    if body.shift_handover_notes is not None:
        changes["shift_handover_notes"] = True
        case["shift_handover_notes"] = body.shift_handover_notes
    if changes:
        case["updated_at"] = _now()
        _append_case_audit(case, body.actor, "soc_meta_changed", changes)
    CASES[case_id] = case
    await _persist_case(case_id, case)
    return case


@app.post("/cases/{case_id}/evidence")
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(...),
    uploaded_by: str = Form(""),
):
    """Store one file on disk; metadata is stored on the case JSON (not file contents)."""
    _validate_case_id(case_id)
    case = await get_case(case_id)
    case.setdefault("evidence", [])
    evidence_id = str(uuid.uuid4())
    orig_name = _safe_filename(file.filename or "upload")
    stored_name = f"{evidence_id}_{orig_name}"
    dest_dir = _evidence_base_dir(case_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / stored_name

    total = 0
    try:
        with open(dest_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_EVIDENCE_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds limit of {MAX_EVIDENCE_BYTES} bytes",
                    )
                out.write(chunk)
    except HTTPException:
        dest_path.unlink(missing_ok=True)
        raise
    except Exception:
        dest_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Failed to store file") from None

    meta = {
        "id": evidence_id,
        "filename": orig_name,
        "stored_name": stored_name,
        "size": total,
        "content_type": (file.content_type or "application/octet-stream")[:200],
        "uploaded_at": _now(),
        "uploaded_by": (uploaded_by or "").strip()[:200] or None,
    }
    case["evidence"].append(meta)
    case["updated_at"] = _now()
    case["timeline"].append(
        {"event": "evidence_uploaded", "at": _now(), "evidence_id": evidence_id, "filename": orig_name}
    )
    _append_case_audit(
        case,
        (uploaded_by or "").strip()[:200] or "system",
        "evidence_uploaded",
        {"evidence_id": evidence_id, "filename": orig_name, "size": total},
    )
    CASES[case_id] = case
    await _persist_case(case_id, case)
    await _emit(
        "evidence_uploaded",
        {"case_id": case_id, "evidence_id": evidence_id, "filename": orig_name, "size": total},
    )
    return meta


@app.get("/cases/{case_id}/evidence/{evidence_id}/file")
async def download_evidence_file(case_id: str, evidence_id: str):
    _validate_case_id(case_id)
    if not _UUID_RE.match(evidence_id.strip()):
        raise HTTPException(status_code=400, detail="Invalid evidence id")
    eid = evidence_id.strip()
    case = await get_case(case_id)
    case.setdefault("evidence", [])
    meta = next((e for e in case["evidence"] if e.get("id") == eid), None)
    if not meta:
        raise HTTPException(status_code=404, detail="Evidence not found")
    path = _resolved_evidence_path(case_id, str(meta["stored_name"]))
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file missing on disk")
    return FileResponse(
        path,
        filename=str(meta.get("filename") or "download"),
        media_type=str(meta.get("content_type") or "application/octet-stream"),
    )


@app.delete("/cases/{case_id}/evidence/{evidence_id}")
async def delete_evidence(case_id: str, evidence_id: str):
    _validate_case_id(case_id)
    if not _UUID_RE.match(evidence_id.strip()):
        raise HTTPException(status_code=400, detail="Invalid evidence id")
    eid = evidence_id.strip()
    case = await get_case(case_id)
    case.setdefault("evidence", [])
    meta = next((e for e in case["evidence"] if e.get("id") == eid), None)
    if not meta:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if case.get("legal_hold"):
        raise HTTPException(
            status_code=423,
            detail="Legal hold is active — evidence cannot be deleted until hold is cleared.",
        )
    path = _resolved_evidence_path(case_id, str(meta["stored_name"]))
    if path.is_file():
        path.unlink()
    case["evidence"] = [e for e in case["evidence"] if e.get("id") != eid]
    case["updated_at"] = _now()
    case["timeline"].append({"event": "evidence_removed", "at": _now(), "evidence_id": eid})
    _append_case_audit(case, "system", "evidence_deleted", {"evidence_id": eid, "filename": meta.get("filename")})
    CASES[case_id] = case
    await _persist_case(case_id, case)
    return {"status": "deleted", "evidence_id": eid}


@app.get("/cases/{case_id}/related")
async def related_cases(case_id: str, window_days: int = 14, limit: int = 15):
    """Suggest other cases with overlapping IOCs (and bonus for shared tags) within a time window."""
    _validate_case_id(case_id)
    me = await get_case(case_id)
    all_c = await _all_cases_decrypted()
    limit = max(1, min(limit, 50))
    window_days = max(0, min(window_days, 365))
    scored: list[tuple[int, dict[str, Any]]] = []
    o_me, t_me = _obs_tuples(me), _tags_lower(me)
    for other in all_c:
        oid = str(other.get("id", ""))
        if oid == case_id:
            continue
        if not _within_case_window(other.get("created_at"), window_days):
            continue
        o_ot, t_ot = _obs_tuples(other), _tags_lower(other)
        shared_o = o_me & o_ot
        shared_t = t_me & t_ot
        score = len(shared_o) * 10 + len(shared_t)
        if score <= 0:
            continue
        reasons: list[str] = []
        if shared_o:
            reasons.append(f"{len(shared_o)} shared IOC(s)")
        if shared_t:
            reasons.append("tags: " + ", ".join(sorted(shared_t)[:6]))
        scored.append(
            (
                score,
                {
                    "id": oid,
                    "title": other.get("title") or oid,
                    "score": score,
                    "reasons": reasons,
                    "created_at": other.get("created_at"),
                },
            )
        )
    scored.sort(key=lambda x: -x[0])
    return {"related_cases": [x[1] for x in scored[:limit]]}


@app.post("/cases/{case_id}/link")
async def link_case(case_id: str, body: CaseLinkBody):
    """Bidirectional link between two cases (metadata + timeline)."""
    _validate_case_id(case_id)
    target = body.target_case_id
    if case_id == target:
        raise HTTPException(status_code=400, detail="Cannot link a case to itself")
    a = await get_case(case_id)
    b = await get_case(target)
    a.setdefault("linked_case_ids", [])
    b.setdefault("linked_case_ids", [])
    act = (body.actor or "").strip()[:200] or "system"
    changed = False
    if target not in a["linked_case_ids"]:
        a["linked_case_ids"].append(target)
        changed = True
    if case_id not in b["linked_case_ids"]:
        b["linked_case_ids"].append(case_id)
        changed = True
    if not changed:
        return {"status": "already_linked", "case_id": case_id, "target_case_id": target}
    now = _now()
    a["updated_at"] = now
    b["updated_at"] = now
    a["timeline"].append({"event": "case_linked", "at": now, "target_case_id": target, "by": act})
    b["timeline"].append({"event": "case_linked", "at": now, "target_case_id": case_id, "by": act})
    _append_case_audit(a, act, "case_linked", {"target_case_id": target})
    _append_case_audit(b, act, "case_linked", {"target_case_id": case_id})
    CASES[case_id] = a
    CASES[target] = b
    await _persist_case(case_id, a)
    await _persist_case(target, b)
    await _emit("case_linked", {"case_id": case_id, "target_case_id": target, "actor": act})
    return {"status": "linked", "case_id": case_id, "target_case_id": target}


@app.get("/cases/{case_id}/investigation-timeline")
async def investigation_timeline(case_id: str):
    """Merged chronological view: timeline + comments + tasks + evidence + source alert."""
    _validate_case_id(case_id)
    case = await get_case(case_id)
    ev: list[dict[str, Any]] = []
    for t in case.get("timeline") or []:
        if isinstance(t, dict):
            ev.append(
                {
                    "at": t.get("at") or "",
                    "kind": "timeline",
                    "label": str(t.get("event", "event")),
                    "detail": t,
                }
            )
    for co in case.get("comments") or []:
        if isinstance(co, dict):
            txt = str(co.get("text") or "")
            ev.append(
                {
                    "at": co.get("at") or "",
                    "kind": "comment",
                    "label": "comment",
                    "detail": {"author": co.get("author"), "text": txt[:400]},
                }
            )
    for tk in case.get("tasks") or []:
        if isinstance(tk, dict):
            ts = tk.get("updated_at") or tk.get("created_at") or ""
            ev.append(
                {
                    "at": ts,
                    "kind": "task",
                    "label": f"task ({tk.get('status', '')})",
                    "detail": {"title": tk.get("title"), "id": tk.get("id")},
                }
            )
    for ei in case.get("evidence") or []:
        if isinstance(ei, dict) and ei.get("uploaded_at"):
            ev.append(
                {
                    "at": ei["uploaded_at"],
                    "kind": "evidence",
                    "label": "evidence",
                    "detail": {"filename": ei.get("filename"), "id": ei.get("id")},
                }
            )
    alt = await _fetch_alert_payload(str(case.get("alert_id") or ""))
    if alt:
        ev.append(
            {
                "at": alt.get("ingested_at") or alt.get("created_at") or "",
                "kind": "source_alert",
                "label": "source alert",
                "detail": {
                    "alert_id": case.get("alert_id"),
                    "title": alt.get("title"),
                    "severity": alt.get("severity"),
                    "source": alt.get("source"),
                },
            }
        )
    ev.sort(key=lambda x: (x.get("at") or "", x.get("kind") or ""))
    return {"events": ev}
