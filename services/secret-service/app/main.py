import os
from datetime import datetime, timezone

import asyncpg
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI(title="Secret Service")
Instrumentator().instrument(app).expose(app)

ALLOW_INSECURE_NO_INTERNAL_TOKEN = os.getenv("ALLOW_INSECURE_NO_INTERNAL_TOKEN", "").strip().lower() in (
    "1",
    "true",
    "yes",
)
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "").strip()
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "")
if not DATA_ENCRYPTION_KEY:
    raise RuntimeError("DATA_ENCRYPTION_KEY is required for secret-service")
if not INTERNAL_SERVICE_TOKEN and not ALLOW_INSECURE_NO_INTERNAL_TOKEN:
    raise RuntimeError(
        "INTERNAL_SERVICE_TOKEN is required. Set ALLOW_INSECURE_NO_INTERNAL_TOKEN=1 for local dev only."
    )

FERNET = Fernet(DATA_ENCRYPTION_KEY.encode())
db_pool: asyncpg.Pool | None = None


class SecretBody(BaseModel):
    value: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encrypt(value: str) -> str:
    return FERNET.encrypt(value.encode()).decode()


def _decrypt(value: str) -> str:
    return FERNET.decrypt(value.encode()).decode()


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


@app.on_event("startup")
async def startup():
    global db_pool
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
        "CREATE TABLE IF NOT EXISTS secrets ("
        "key TEXT PRIMARY KEY, value_encrypted TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"
    )


@app.on_event("shutdown")
async def shutdown():
    if db_pool:
        await db_pool.close()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/secrets")
async def list_secrets():
    assert db_pool
    rows = await db_pool.fetch("SELECT key, updated_at FROM secrets ORDER BY key")
    return [{"key": r["key"], "updated_at": r["updated_at"].isoformat()} for r in rows]


@app.get("/secrets/{key}")
async def get_secret(key: str):
    assert db_pool
    row = await db_pool.fetchrow("SELECT value_encrypted FROM secrets WHERE key = $1", key)
    if not row:
        raise HTTPException(status_code=404, detail="Secret not found")
    return {"key": key, "value": _decrypt(row["value_encrypted"])}


@app.put("/secrets/{key}")
async def set_secret(key: str, body: SecretBody):
    assert db_pool
    await db_pool.execute(
        "INSERT INTO secrets(key, value_encrypted, updated_at) VALUES($1, $2, now()) "
        "ON CONFLICT (key) DO UPDATE SET value_encrypted = EXCLUDED.value_encrypted, updated_at = now()",
        key,
        _encrypt(body.value),
    )
    return {"status": "updated", "key": key, "updated_at": _now()}


@app.delete("/secrets/{key}")
async def delete_secret(key: str):
    assert db_pool
    result = await db_pool.execute("DELETE FROM secrets WHERE key = $1", key)
    if result.endswith("0"):
        raise HTTPException(status_code=404, detail="Secret not found")
    return {"status": "deleted", "key": key}
