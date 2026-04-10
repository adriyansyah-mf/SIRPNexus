import json
import os
import re
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import asyncpg
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
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")
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
    if INTERNAL_SERVICE_TOKEN and request.headers.get("x-internal-token") != INTERNAL_SERVICE_TOKEN:
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
    return case


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
    }


@app.post("/cases")
async def create_case(body: CaseCreate):
    """Create a case without linking an alert (manual / proactive SOC case)."""
    case_id = str(uuid.uuid4())
    case = _build_case(case_id, body.title, body.description, body.severity, body.owner, tags=body.tags)
    case["timeline"] = [{"event": "case_created_manual", "at": _now()}]
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
    CASES[case_id] = case
    await _persist_case(case_id, case)
    await _emit("created", {"case": case})
    return case


@app.post("/cases/{case_id}/assign")
async def assign_case(case_id: str, body: Assignment):
    case = await get_case(case_id)
    case["assigned_to"] = body.assigned_to
    case["assigned_by"] = body.assigned_by
    case["assigned_at"] = _now()
    case["updated_at"] = _now()
    case["timeline"].append({"event": "assigned", "at": _now(), **body.model_dump()})
    CASES[case_id] = case
    await _persist_case(case_id, case)
    await _emit("assigned", {"case_id": case_id, "assignment": body.model_dump()})
    return case


@app.post("/cases/{case_id}/status")
async def update_status(case_id: str, body: StatusBody):
    case = await get_case(case_id)
    if case["assigned_to"] and body.actor not in {case["assigned_to"], "admin"}:
        raise HTTPException(status_code=403, detail="Only owner or admin can update")
    case["status"] = body.status
    case["updated_at"] = _now()
    case["timeline"].append({"event": "status_changed", "at": _now(), **body.model_dump()})
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
    CASES[case_id] = case
    await _persist_case(case_id, case)
    await _emit("comment_added", {"case_id": case_id, "comment": comment})
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
    CASES[case_id] = case
    await _persist_case(case_id, case)
    await _emit("task_added", {"case_id": case_id, "task": task})
    return task


@app.put("/cases/{case_id}/tasks/{task_id}")
async def update_task(case_id: str, task_id: str, body: TaskStatusBody):
    case = await get_case(case_id)
    for task in case.get("tasks", []):
        if task["id"] == task_id:
            task["status"] = body.status
            task["updated_at"] = _now()
            case["updated_at"] = _now()
            case["timeline"].append({"event": "task_updated", "at": _now(), "task_id": task_id, "status": body.status})
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
    CASES[case_id] = case
    await _persist_case(case_id, case)
    return {"status": "deleted", "task_id": task_id}


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
    path = _resolved_evidence_path(case_id, str(meta["stored_name"]))
    if path.is_file():
        path.unlink()
    case["evidence"] = [e for e in case["evidence"] if e.get("id") != eid]
    case["updated_at"] = _now()
    case["timeline"].append({"event": "evidence_removed", "at": _now(), "evidence_id": eid})
    CASES[case_id] = case
    await _persist_case(case_id, case)
    return {"status": "deleted", "evidence_id": eid}
