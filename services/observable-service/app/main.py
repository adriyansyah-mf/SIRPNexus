import asyncio
import json
import os
from datetime import datetime, timezone

import asyncpg
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from elasticsearch import AsyncElasticsearch
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from redis.asyncio import Redis

app = FastAPI(title="Observable Service")
Instrumentator().instrument(app).expose(app)

producer: AIOKafkaProducer | None = None
consumer: AIOKafkaConsumer | None = None
redis_client: Redis | None = None
es: AsyncElasticsearch | None = None
db_pool: asyncpg.Pool | None = None

OBSERVABLES: list[dict] = []
KAFKA = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
ELASTIC = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.on_event("startup")
async def startup():
    global producer, consumer, redis_client, es, db_pool
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA)
    await producer.start()
    consumer = AIOKafkaConsumer("observables.created", bootstrap_servers=KAFKA, group_id="observable-service")
    await consumer.start()
    redis_client = Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))
    es = AsyncElasticsearch(hosts=[ELASTIC])
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
        "CREATE TABLE IF NOT EXISTS observables ("
        "id TEXT PRIMARY KEY, payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
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
    if es:
        await es.close()
    if db_pool:
        await db_pool.close()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.middleware("http")
async def enforce_internal_token(request: Request, call_next):
    if request.url.path in {"/health", "/metrics"}:
        return await call_next(request)
    if INTERNAL_SERVICE_TOKEN and request.headers.get("x-internal-token") != INTERNAL_SERVICE_TOKEN:
        return JSONResponse(status_code=401, content={"detail": "Invalid internal service token"})
    return await call_next(request)


def _validate_ioc(data: dict) -> None:
    if data.get("type") not in {"ip", "domain", "url", "hash", "email"}:
        raise HTTPException(status_code=400, detail="Unsupported IOC type")
    if not data.get("value"):
        raise HTTPException(status_code=400, detail="IOC value is required")


@app.get("/observables")
async def list_observables():
    if db_pool:
        rows = await db_pool.fetch("SELECT payload FROM observables ORDER BY created_at DESC LIMIT 1000")
        return [dict(r["payload"]) for r in rows]
    return OBSERVABLES


@app.post("/observables")
async def create_observable(data: dict):
    _validate_ioc(data)
    assert redis_client and producer and es
    key = f"ioc:{data['type']}:{data['value']}"
    created = await redis_client.set(key, "1", ex=86400, nx=True)
    doc_id = f"{data['type']}:{data['value']}"
    doc = {**data, "id": doc_id, "created_at": _now(), "new": bool(created)}
    OBSERVABLES.append(doc)
    if db_pool:
        await db_pool.execute(
            "INSERT INTO observables(id, payload, created_at) VALUES($1, $2::jsonb, now()) "
            "ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload",
            doc_id,
            json.dumps(doc),
        )
    await es.index(index="observables", document=doc)
    await producer.send_and_wait("analyzers.jobs", json.dumps(doc).encode())
    return doc


import logging
logger = logging.getLogger("sirp.observable")


async def worker():
    assert consumer
    async for msg in consumer:
        try:
            data = json.loads(msg.value.decode())
            await create_observable(data)
        except HTTPException as exc:
            logger.warning("observable worker skipped IOC: %s (HTTP %d)", exc.detail, exc.status_code)
        except json.JSONDecodeError as exc:
            logger.error("observable worker: malformed JSON message: %s", exc)
        except Exception as exc:
            logger.exception("observable worker unexpected error: %s", exc)
