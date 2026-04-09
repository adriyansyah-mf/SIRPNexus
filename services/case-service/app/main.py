import json
import os
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg
from aiokafka import AIOKafkaProducer
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI(title="Case Service")
Instrumentator().instrument(app).expose(app)
producer: AIOKafkaProducer | None = None
db_pool: asyncpg.Pool | None = None
KAFKA = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "")
FERNET = Fernet(DATA_ENCRYPTION_KEY.encode()) if DATA_ENCRYPTION_KEY else None

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
    alert_id: str
    title: str
    description: str
    observables: list[dict[str, Any]] = []
    tags: list[str] = []
    severity: str = "medium"
    owner: str = ""


class CaseCreate(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"
    owner: str = ""
    tags: list[str] = []


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
        return [_decrypt_case_payload(dict(r["payload"])) for r in rows]
    return list(CASES.values())


@app.get("/cases/{case_id}")
async def get_case(case_id: str):
    case = CASES.get(case_id)
    if not case and db_pool:
        row = await db_pool.fetchrow("SELECT payload FROM cases WHERE id = $1", case_id)
        if row:
            case = _decrypt_case_payload(dict(row["payload"]))
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
    }


@app.post("/cases")
async def create_case(body: CaseCreate):
    case_id = str(uuid.uuid4())
    case = _build_case(case_id, body.title, body.description, body.severity, body.owner, tags=body.tags)
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
