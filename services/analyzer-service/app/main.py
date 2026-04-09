import asyncio
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

import asyncpg
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from redis.asyncio import Redis
from tenacity import retry, stop_after_attempt, wait_exponential

from app.analyzers.engine import run_analysis

app = FastAPI(title="Analyzer Service")
Instrumentator().instrument(app).expose(app)

producer: AIOKafkaProducer | None = None
consumer: AIOKafkaConsumer | None = None
redis_client: Redis | None = None
db_pool: asyncpg.Pool | None = None
KAFKA = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _jsonb_to_dict(raw: Any) -> dict[str, Any]:
    """Postgres JSONB via asyncpg may be dict or a JSON string depending on driver/setup."""
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return dict(decoded) if isinstance(decoded, dict) else {}
    if isinstance(raw, (bytes, bytearray)):
        try:
            decoded = json.loads(raw.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        return dict(decoded) if isinstance(decoded, dict) else {}
    return {}


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
async def _publish(payload: dict):
    assert producer
    await producer.send_and_wait("analyzers.results", json.dumps(payload, default=str).encode())


async def _publish_dlq(payload: dict):
    assert producer
    await producer.send_and_wait("analyzers.jobs.dlq", json.dumps(payload, default=str).encode())


async def _circuit_open(key: str) -> bool:
    assert redis_client
    return await redis_client.get(f"circuit:{key}") == b"open"


async def _trip_circuit(key: str):
    assert redis_client
    await redis_client.set(f"circuit:{key}", "open", ex=60)


def _job_id(job: dict) -> str:
    payload = json.dumps(
        {
            "alert_id": job.get("alert_id"),
            "type": job.get("type"),
            "value": job.get("value"),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


async def _already_processed(job: dict) -> bool:
    if not db_pool:
        return False
    row = await db_pool.fetchrow("SELECT id FROM analyzed_jobs WHERE id = $1", _job_id(job))
    return row is not None


async def _mark_processed(job: dict, status: str):
    if not db_pool:
        return
    await db_pool.execute(
        "INSERT INTO analyzed_jobs(id, status, created_at) VALUES($1, $2, now()) "
        "ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status",
        _job_id(job),
        status,
    )


async def _store_result(job: dict, status: str, result: dict | None = None, error: str | None = None):
    if not db_pool:
        return
    await db_pool.execute(
        "INSERT INTO analyzer_results(job_id, alert_id, ioc_type, ioc_value, status, result_payload, error, created_at) "
        "VALUES($1, $2, $3, $4, $5, $6::jsonb, $7, now()) "
        "ON CONFLICT (job_id) DO UPDATE SET "
        "status = EXCLUDED.status, result_payload = EXCLUDED.result_payload, error = EXCLUDED.error",
        _job_id(job),
        job.get("alert_id"),
        job.get("type"),
        job.get("value"),
        status,
        json.dumps(result or {}),
        error,
    )


@app.on_event("startup")
async def startup():
    global producer, consumer, redis_client, db_pool
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA)
    await producer.start()
    consumer = AIOKafkaConsumer("analyzers.jobs", bootstrap_servers=KAFKA, group_id="analyzer-service")
    await consumer.start()
    redis_client = Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))
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
        "CREATE TABLE IF NOT EXISTS analyzed_jobs ("
        "id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
    )
    await db_pool.execute(
        "CREATE TABLE IF NOT EXISTS analyzer_results ("
        "job_id TEXT PRIMARY KEY, "
        "alert_id TEXT, "
        "ioc_type TEXT NOT NULL, "
        "ioc_value TEXT NOT NULL, "
        "status TEXT NOT NULL, "
        "result_payload JSONB NOT NULL DEFAULT '{}'::jsonb, "
        "error TEXT, "
        "created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
    )
    asyncio.create_task(worker())


@app.on_event("shutdown")
async def shutdown():
    if consumer:
        await consumer.stop()
    if producer:
        await producer.stop()
    if redis_client:
        await redis_client.close()
    if db_pool:
        await db_pool.close()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.middleware("http")
async def enforce_internal_token(request: Request, call_next):
    if request.url.path in {"/health", "/metrics"} or request.url.path.startswith("/results"):
        return await call_next(request)
    if INTERNAL_SERVICE_TOKEN and request.headers.get("x-internal-token") != INTERNAL_SERVICE_TOKEN:
        return JSONResponse(status_code=401, content={"detail": "Invalid internal service token"})
    return await call_next(request)


@app.get("/results")
async def list_results(alert_id: str | None = None, limit: int = 200):
    if not db_pool:
        return []
    if alert_id:
        rows = await db_pool.fetch(
            "SELECT alert_id, ioc_type, ioc_value, status, result_payload, error, created_at "
            "FROM analyzer_results WHERE alert_id = $1 ORDER BY created_at DESC LIMIT $2",
            alert_id,
            limit,
        )
    else:
        rows = await db_pool.fetch(
            "SELECT alert_id, ioc_type, ioc_value, status, result_payload, error, created_at "
            "FROM analyzer_results ORDER BY created_at DESC LIMIT $1",
            limit,
        )
    return [
        {
            "alert_id": r["alert_id"],
            "type": r["ioc_type"],
            "value": r["ioc_value"],
            "status": r["status"],
            "result": _jsonb_to_dict(r["result_payload"]),
            "error": r["error"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]


async def worker():
    assert consumer
    async for msg in consumer:
        job = json.loads(msg.value.decode())
        ioc_type = job.get("type")
        if await _already_processed(job):
            await _publish({"status": "duplicate", "job": job, "at": _now()})
            await _store_result(job, "duplicate", result={"note": "already processed"})
            continue
        if await _circuit_open(ioc_type):
            await _publish({"status": "skipped", "reason": "circuit_open", "job": job, "at": _now()})
            await _mark_processed(job, "skipped")
            await _store_result(job, "skipped", result={"reason": "circuit_open"})
            continue
        try:
            result = await asyncio.wait_for(run_analysis(job), timeout=40)
            await _publish({"status": "ok", "job": job, "result": result, "at": _now()})
            await _mark_processed(job, "ok")
            await _store_result(job, "ok", result=result)
        except Exception as exc:
            await _trip_circuit(ioc_type)
            await _publish_dlq({"job": job, "error": str(exc), "at": _now()})
            await _publish({"status": "error", "job": job, "error": str(exc), "at": _now()})
            await _mark_processed(job, "error")
            await _store_result(job, "error", error=str(exc))
