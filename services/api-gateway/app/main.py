import asyncio
import json
import logging
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import asyncpg
import bcrypt
import httpx
from aiokafka import AIOKafkaConsumer
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from jose import jwt
from jose.exceptions import JWTError
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger("sirp.gateway")

# ── Config — fail-fast on missing critical secrets ────────────────────────────
APP_AUTH_JWT_SECRET: str = os.getenv("APP_AUTH_JWT_SECRET", "")
if not APP_AUTH_JWT_SECRET:
    logger.critical("APP_AUTH_JWT_SECRET is not set — refusing to start")
    sys.exit(1)

ALLOW_INSECURE_NO_INTERNAL_TOKEN = os.getenv("ALLOW_INSECURE_NO_INTERNAL_TOKEN", "").strip().lower() in (
    "1",
    "true",
    "yes",
)
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "").strip()
INBOUND_WEBHOOK_TOKEN = os.getenv("INBOUND_WEBHOOK_TOKEN", "").strip()
ALLOW_INGEST_WITHOUT_TOKEN = os.getenv("ALLOW_INGEST_WITHOUT_TOKEN", "").strip().lower() in ("1", "true", "yes")

if not INTERNAL_SERVICE_TOKEN and not ALLOW_INSECURE_NO_INTERNAL_TOKEN:
    logger.critical(
        "INTERNAL_SERVICE_TOKEN is not set — refusing to start (set ALLOW_INSECURE_NO_INTERNAL_TOKEN=1 for dev only)"
    )
    sys.exit(1)

AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "sirp-api")
OIDC_ISSUER = os.getenv("KEYCLOAK_ISSUER", "")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(4 * 1024 * 1024)))  # 4 MB default
# Multipart case evidence uploads (POST …/cases/cases/{id}/evidence)
MAX_CASE_EVIDENCE_BYTES = int(os.getenv("MAX_CASE_EVIDENCE_BYTES", str(32 * 1024 * 1024)))

# Strip client-supplied spoofing / privilege headers before proxying to internal services.
_STRIP_FROM_CLIENT = frozenset(
    {
        "x-internal-token",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "forwarded",
        "x-sirp-ingest-client-ip",
    }
)


def _forward_headers_from_request(request: Request) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk == "host" or lk in _STRIP_FROM_CLIENT:
            continue
        out[k] = v
    return out


# ── Service map ───────────────────────────────────────────────────────────────
def _env_url(name: str, default: str) -> str:
    return (os.getenv(name) or "").strip() or default


SERVICE_MAP = {
    "alerts":        _env_url("ALERT_SERVICE_URL",        "http://alert-service:8001"),
    "cases":         _env_url("CASE_SERVICE_URL",         "http://case-service:8001"),
    "observables":   _env_url("OBSERVABLE_SERVICE_URL",   "http://observable-service:8001"),
    "automation":    _env_url("AUTOMATION_SERVICE_URL",   "http://automation-service:8001"),
    "notifications": _env_url("NOTIFICATION_SERVICE_URL", "http://notification-service:8001"),
    "secrets":       _env_url("SECRET_SERVICE_URL",       "http://secret-service:8001"),
}

VALID_ROLES = {"admin", "analyst", "responder", "readonly"}

POSTGRES_DSN = {
    "host":     os.getenv("POSTGRES_HOST", "postgres"),
    "port":     int(os.getenv("POSTGRES_PORT", "5432")),
    "user":     os.getenv("POSTGRES_USER", "sirp"),
    "password": os.getenv("POSTGRES_PASSWORD", "sirp"),
    "database": os.getenv("POSTGRES_DB", "sirp"),
}

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["300/minute"])

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="SIRP API Gateway", docs_url=None, redoc_url=None)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

Instrumentator().instrument(app).expose(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Webhook-Token"],
)

# ── Security response headers ─────────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# ── Request body size limit ───────────────────────────────────────────────────
@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if not content_length:
        return await call_next(request)
    cl = int(content_length)
    path = request.url.path
    is_case_evidence_upload = (
        request.method == "POST"
        and path.startswith("/cases/cases/")
        and path.rstrip("/").endswith("/evidence")
    )
    max_bytes = MAX_CASE_EVIDENCE_BYTES if is_case_evidence_upload else MAX_BODY_BYTES
    if cl > max_bytes:
        return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    return await call_next(request)

# ── User DB ───────────────────────────────────────────────────────────────────
_user_pool: asyncpg.Pool | None = None


async def _get_pool() -> asyncpg.Pool:
    global _user_pool
    if _user_pool is None:
        _user_pool = await asyncpg.create_pool(**POSTGRES_DSN, min_size=1, max_size=4)
        await _user_pool.execute(
            """
            CREATE TABLE IF NOT EXISTS sirp_users (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'analyst',
                created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
                login_attempts INT NOT NULL DEFAULT 0,
                locked_until   TIMESTAMPTZ
            )
            """
        )
        # Live migration: add lockout columns if they don't exist yet
        await _user_pool.execute(
            "ALTER TABLE sirp_users ADD COLUMN IF NOT EXISTS login_attempts INT NOT NULL DEFAULT 0"
        )
        await _user_pool.execute(
            "ALTER TABLE sirp_users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ"
        )
        await _user_pool.execute(
            """
            CREATE TABLE IF NOT EXISTS sirp_audit_log (
                id BIGSERIAL PRIMARY KEY,
                at TIMESTAMPTZ NOT NULL DEFAULT now(),
                actor TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT 'mutation',
                resource_type TEXT,
                resource_id TEXT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status_code INT NOT NULL,
                detail JSONB
            )
            """
        )
        await _user_pool.execute(
            "CREATE INDEX IF NOT EXISTS sirp_audit_log_at_idx ON sirp_audit_log (at DESC)"
        )
        await _user_pool.execute(
            "CREATE INDEX IF NOT EXISTS sirp_audit_log_actor_idx ON sirp_audit_log (actor)"
        )
        await _user_pool.execute(
            """
            CREATE TABLE IF NOT EXISTS sirp_saved_hunts (
                id TEXT PRIMARY KEY,
                owner_username TEXT NOT NULL,
                label TEXT NOT NULL,
                query TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        await _user_pool.execute(
            "CREATE INDEX IF NOT EXISTS sirp_saved_hunts_owner_idx ON sirp_saved_hunts (owner_username, created_at DESC)"
        )
        await _user_pool.execute(
            """
            CREATE TABLE IF NOT EXISTS sirp_ops_snapshots (
                id BIGSERIAL PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                snapshot JSONB NOT NULL
            )
            """
        )
        await _user_pool.execute(
            "CREATE INDEX IF NOT EXISTS sirp_ops_snapshots_created_idx ON sirp_ops_snapshots (created_at DESC)"
        )
        await _user_pool.execute(
            """
            CREATE TABLE IF NOT EXISTS sirp_chain_of_custody (
                id BIGSERIAL PRIMARY KEY,
                at TIMESTAMPTZ NOT NULL DEFAULT now(),
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                case_id TEXT,
                evidence_id TEXT,
                detail JSONB
            )
            """
        )
        await _user_pool.execute(
            "CREATE INDEX IF NOT EXISTS sirp_custody_case_idx ON sirp_chain_of_custody (case_id, at DESC)"
        )
        await _user_pool.execute(
            """
            CREATE TABLE IF NOT EXISTS sirp_shift_reports (
                id UUID PRIMARY KEY,
                author TEXT NOT NULL,
                summary TEXT NOT NULL,
                case_refs JSONB,
                alert_refs JSONB,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        await _user_pool.execute(
            "CREATE INDEX IF NOT EXISTS sirp_shift_reports_at_idx ON sirp_shift_reports (created_at DESC)"
        )
        await _user_pool.execute(
            """
            CREATE TABLE IF NOT EXISTS sirp_case_watchers (
                case_id TEXT NOT NULL,
                username TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                PRIMARY KEY (case_id, username)
            )
            """
        )
        await _user_pool.execute(
            """
            CREATE TABLE IF NOT EXISTS sirp_playbook_run_requests (
                id UUID PRIMARY KEY,
                playbook_id TEXT NOT NULL,
                requester TEXT NOT NULL,
                case_id TEXT,
                event_payload JSONB,
                status TEXT NOT NULL DEFAULT 'pending',
                approver TEXT,
                resolution_note TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                resolved_at TIMESTAMPTZ
            )
            """
        )
        await _user_pool.execute(
            "CREATE INDEX IF NOT EXISTS sirp_pb_req_status_idx ON sirp_playbook_run_requests (status, created_at DESC)"
        )
        await _user_pool.execute(
            """
            CREATE TABLE IF NOT EXISTS sirp_mention_events (
                id BIGSERIAL PRIMARY KEY,
                at TIMESTAMPTZ NOT NULL DEFAULT now(),
                case_id TEXT NOT NULL,
                comment_id TEXT NOT NULL,
                author TEXT NOT NULL,
                mentioned_username TEXT NOT NULL,
                excerpt TEXT
            )
            """
        )
        await _user_pool.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS sirp_mention_unique_idx ON sirp_mention_events "
            "(case_id, comment_id, mentioned_username)"
        )
        await _user_pool.execute(
            "CREATE INDEX IF NOT EXISTS sirp_mention_user_idx ON sirp_mention_events (mentioned_username, at DESC)"
        )
        await _user_pool.execute(
            """
            CREATE TABLE IF NOT EXISTS sirp_entity_edges (
                src_kind TEXT NOT NULL,
                src_id TEXT NOT NULL,
                dst_kind TEXT NOT NULL,
                dst_id TEXT NOT NULL,
                rel TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                PRIMARY KEY (src_kind, src_id, dst_kind, dst_id, rel)
            )
            """
        )
        await _user_pool.execute(
            "CREATE INDEX IF NOT EXISTS sirp_edges_dst_idx ON sirp_entity_edges (dst_kind, dst_id)"
        )
        await _user_pool.execute(
            "ALTER TABLE sirp_playbook_run_requests ADD COLUMN IF NOT EXISTS approval_chain JSONB"
        )
        await _user_pool.execute(
            "ALTER TABLE sirp_playbook_run_requests ADD COLUMN IF NOT EXISTS current_step INT NOT NULL DEFAULT 0"
        )
        await _user_pool.execute(
            "ALTER TABLE sirp_playbook_run_requests ADD COLUMN IF NOT EXISTS step_approvals JSONB DEFAULT '[]'::jsonb"
        )
        existing = await _user_pool.fetchval("SELECT count(*) FROM sirp_users")
        if existing == 0:
            admin_user = os.getenv("INITIAL_ADMIN_USERNAME", "admin")
            admin_pass = os.getenv("INITIAL_ADMIN_PASSWORD", "changeme")
            await _user_pool.execute(
                "INSERT INTO sirp_users(username, password_hash, role) VALUES($1,$2,'admin') ON CONFLICT DO NOTHING",
                admin_user,
                _hash_password(admin_pass),
            )
    return _user_pool


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except Exception:
        return False


@app.on_event("startup")
async def _startup():
    await _get_pool()
    logger.info("API Gateway ready")


# ── JWT helpers ───────────────────────────────────────────────────────────────
def _sign_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "preferred_username": username,
        "roles": [role],
        "realm_access": {"roles": [role]},
        "iat": int(time.time()),
        "exp": int(time.time()) + 28800,
        "aud": AUDIENCE,
        "iss": "sirp-local-auth",
    }
    return jwt.encode(payload, APP_AUTH_JWT_SECRET, algorithm="HS256")


def _decode_token(token: str) -> dict:
    """HS256 (local /auth/login) by default; RS256 + JWKS only when token alg is RS256 and OIDC_ISSUER is set."""
    try:
        header = jwt.get_unverified_header(token)
        alg = (header.get("alg") or "").upper()
    except Exception:
        alg = ""

    issuer = OIDC_ISSUER.rstrip("/") if OIDC_ISSUER else ""

    if alg == "RS256" and issuer:
        jwks_url = f"{issuer}/protocol/openid-connect/certs"
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(jwks_url)
                resp.raise_for_status()
                jwks = resp.json()
        except httpx.ConnectError as exc:
            raise HTTPException(
                status_code=503,
                detail="OIDC issuer unreachable — use local login tokens only, or fix KEYCLOAK_ISSUER / network",
            ) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=503, detail="OIDC JWKS request failed") from exc
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
        if not key:
            raise HTTPException(status_code=401, detail="Token key mismatch")
        try:
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=AUDIENCE, issuer=issuer)
        except JWTError as exc:
            raise HTTPException(status_code=401, detail="Invalid or expired token") from exc
        if "realm_access" not in claims and "roles" in claims:
            claims["realm_access"] = {"roles": claims["roles"]}
        return claims

    try:
        claims = jwt.decode(token, APP_AUTH_JWT_SECRET, algorithms=["HS256"], audience=AUDIENCE)
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc
    if "realm_access" not in claims and "roles" in claims:
        claims["realm_access"] = {"roles": claims["roles"]}
    return claims


def _require_role(claims: dict, allowed: set[str]) -> None:
    token_roles = set(claims.get("realm_access", {}).get("roles", []))
    if not (token_roles & allowed):
        raise HTTPException(status_code=403, detail="Insufficient permissions")


def _require_role_soft(claims: dict, allowed: set[str]) -> bool:
    """Return True if user has a matching role, False otherwise (no exception)."""
    token_roles = set(claims.get("realm_access", {}).get("roles", []))
    return bool(token_roles & allowed)


def _require_admin_from_request(request: Request) -> dict:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization required")
    claims = _decode_token(auth.split(" ", 1)[1])
    _require_role(claims, {"admin"})
    return claims


_UUID_RE = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", re.I)


async def _audit_append(
    actor: str,
    method: str,
    path: str,
    status_code: int,
    resource_type: str | None,
    resource_id: str | None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Append-only audit row (never UPDATE/DELETE from application code)."""
    try:
        pool = await _get_pool()
        await pool.execute(
            "INSERT INTO sirp_audit_log(actor, action, resource_type, resource_id, method, path, status_code, detail) "
            "VALUES($1, 'mutation', $2, $3, $4, $5, $6, $7::jsonb)",
            actor[:200],
            resource_type,
            resource_id,
            method,
            path[:2000],
            status_code,
            json.dumps(detail or {}),
        )
    except Exception as exc:
        logger.warning("audit log insert failed: %s", exc)


def _audit_resource_from_proxy(service: str, path: str) -> tuple[str | None, str | None]:
    m = _UUID_RE.search(path)
    rid = m.group(0) if m else None
    st = {
        "cases": "case",
        "alerts": "alert",
        "observables": "observable",
        "automation": "automation",
        "secrets": "secret",
        "notifications": "notification",
    }.get(service)
    return st, rid


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok"}


# ── Auth: login (rate-limited) ────────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


@app.post("/auth/login")
@limiter.limit("10/minute")
async def auth_login(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")

    pool = await _get_pool()
    row = await pool.fetchrow(
        "SELECT password_hash, role, login_attempts, locked_until FROM sirp_users WHERE username=$1",
        username,
    )
    # Return same error for unknown user (timing-safe)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Lockout check
    if row["locked_until"] and row["locked_until"].timestamp() > time.time():
        raise HTTPException(status_code=429, detail="Account temporarily locked. Try again later.")

    if not _verify_password(password, row["password_hash"]):
        attempts = (row["login_attempts"] or 0) + 1
        if attempts >= MAX_LOGIN_ATTEMPTS:
            await pool.execute(
                "UPDATE sirp_users SET login_attempts=$1, locked_until=now()+interval '%d seconds', updated_at=now() WHERE username=$2" % LOCKOUT_SECONDS,
                attempts, username,
            )
            logger.warning("Account %s locked after %d failed attempts", username, attempts)
            raise HTTPException(status_code=429, detail="Account temporarily locked after too many failed attempts.")
        else:
            await pool.execute(
                "UPDATE sirp_users SET login_attempts=$1, updated_at=now() WHERE username=$2",
                attempts, username,
            )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Success — reset counter
    await pool.execute(
        "UPDATE sirp_users SET login_attempts=0, locked_until=NULL, updated_at=now() WHERE username=$1",
        username,
    )
    token = _sign_token(username, row["role"])
    logger.info("Login success: %s role=%s", username, row["role"])
    return {"access_token": token, "token_type": "Bearer", "expires_in": 28800, "role": row["role"]}


@app.get("/auth/me")
async def auth_me(request: Request):
    """JWT claims for the current session (Bearer or forwarded from BFF cookie)."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization required")
    claims = _decode_token(auth.split(" ", 1)[1])
    roles = list(claims.get("realm_access", {}).get("roles", []) or [])
    user = str(claims.get("preferred_username") or claims.get("sub") or "").strip() or "user"
    return {"sub": claims.get("sub"), "preferred_username": user, "roles": roles}


# ── Auth: user management (admin only) ───────────────────────────────────────
@app.get("/auth/users")
async def list_users(request: Request):
    _require_admin_from_request(request)
    pool = await _get_pool()
    rows = await pool.fetch(
        "SELECT username, role, created_at, updated_at, login_attempts, locked_until FROM sirp_users ORDER BY created_at DESC"
    )
    return [
        {
            "username": r["username"],
            "role": r["role"],
            "locked": r["locked_until"] is not None and r["locked_until"].timestamp() > time.time(),
            "login_attempts": r["login_attempts"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
        }
        for r in rows
    ]


@app.post("/auth/users")
async def create_user(request: Request):
    claims = _require_admin_from_request(request)
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "").strip()
    role = (body.get("role") or "analyst").strip().lower()

    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Valid: {sorted(VALID_ROLES)}")

    pool = await _get_pool()
    try:
        await pool.execute(
            "INSERT INTO sirp_users(username, password_hash, role) VALUES($1,$2,$3)",
            username, _hash_password(password), role,
        )
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail=f"User '{username}' already exists")
    actor = claims.get("preferred_username") or claims.get("sub") or "?"
    await _audit_append(actor, "POST", "/auth/users", 200, "user", username, {"op": "user_create", "role": role})
    return {"username": username, "role": role, "status": "created"}


@app.put("/auth/users/{username}/role")
async def update_user_role(username: str, request: Request):
    claims = _require_admin_from_request(request)
    body = await request.json()
    role = (body.get("role") or "").strip().lower()
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Valid: {sorted(VALID_ROLES)}")

    pool = await _get_pool()
    result = await pool.execute(
        "UPDATE sirp_users SET role=$1, updated_at=now() WHERE username=$2", role, username
    )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    actor = claims.get("preferred_username") or claims.get("sub") or "?"
    await _audit_append(actor, "PUT", f"/auth/users/{username}/role", 200, "user", username, {"op": "role_change", "role": role})
    return {"username": username, "role": role, "status": "updated"}


@app.put("/auth/users/{username}/password")
async def update_user_password(username: str, request: Request):
    claims = _require_admin_from_request(request)
    body = await request.json()
    password = (body.get("password") or "").strip()
    if not password:
        raise HTTPException(status_code=400, detail="password required")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if claims.get("sub") != username:
        _require_role(claims, {"admin"})

    pool = await _get_pool()
    result = await pool.execute(
        "UPDATE sirp_users SET password_hash=$1, login_attempts=0, locked_until=NULL, updated_at=now() WHERE username=$2",
        _hash_password(password), username,
    )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    actor = claims.get("preferred_username") or claims.get("sub") or "?"
    await _audit_append(actor, "PUT", f"/auth/users/{username}/password", 200, "user", username, {"op": "password_reset"})
    return {"username": username, "status": "password updated"}


@app.post("/auth/users/{username}/unlock")
async def unlock_user(username: str, request: Request):
    claims = _require_admin_from_request(request)
    pool = await _get_pool()
    result = await pool.execute(
        "UPDATE sirp_users SET login_attempts=0, locked_until=NULL, updated_at=now() WHERE username=$1", username
    )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    actor = claims.get("preferred_username") or claims.get("sub") or "?"
    await _audit_append(actor, "POST", f"/auth/users/{username}/unlock", 200, "user", username, {"op": "unlock"})
    return {"username": username, "status": "unlocked"}


@app.delete("/auth/users/{username}")
async def delete_user(username: str, request: Request):
    claims = _require_admin_from_request(request)
    if claims.get("sub") == username:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    pool = await _get_pool()
    result = await pool.execute("DELETE FROM sirp_users WHERE username=$1", username)
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    actor = claims.get("preferred_username") or claims.get("sub") or "?"
    await _audit_append(actor, "DELETE", f"/auth/users/{username}", 200, "user", username, {"op": "user_delete"})
    return {"username": username, "status": "deleted"}


@app.get("/audit/events")
async def list_audit_events(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    actor: str | None = None,
    resource_type: str | None = None,
):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization required")
    claims = _decode_token(auth.split(" ", 1)[1])
    _require_role(claims, {"admin", "analyst", "responder", "readonly"})
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    pool = await _get_pool()
    where: list[str] = []
    args: list[Any] = []
    p = 0
    if actor:
        p += 1
        args.append(actor)
        where.append(f"actor = ${p}")
    if resource_type:
        p += 1
        args.append(resource_type)
        where.append(f"resource_type = ${p}")
    p += 1
    args.append(limit)
    lim_p = p
    p += 1
    args.append(offset)
    off_p = p
    wh = ("WHERE " + " AND ".join(where)) if where else ""
    rows = await pool.fetch(
        f"SELECT id, at, actor, resource_type, resource_id, method, path, status_code, detail "
        f"FROM sirp_audit_log {wh} ORDER BY at DESC LIMIT ${lim_p} OFFSET ${off_p}",
        *args,
    )
    return [
        {
            "id": r["id"],
            "at": r["at"].isoformat() if r["at"] else None,
            "actor": r["actor"],
            "resource_type": r["resource_type"],
            "resource_id": r["resource_id"],
            "method": r["method"],
            "path": r["path"],
            "status_code": r["status_code"],
            "detail": r["detail"],
        }
        for r in rows
    ]


def _search_match(haystack: str, q: str) -> bool:
    return q.lower() in haystack.lower()


@app.get("/search")
async def global_search(request: Request, q: str, limit_per: int = 20):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization required")
    claims = _decode_token(auth.split(" ", 1)[1])
    _require_role(claims, {"analyst", "responder", "admin", "readonly"})
    qn = (q or "").strip()
    if len(qn) < 2:
        raise HTTPException(status_code=400, detail="Query must be at least 2 characters")
    cap = max(1, min(limit_per, 50))
    headers: dict[str, str] = {}
    if INTERNAL_SERVICE_TOKEN:
        headers["x-internal-token"] = INTERNAL_SERVICE_TOKEN

    async def _get_json(url: str) -> list[Any]:
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.get(url, headers=headers)
            if r.status_code != 200:
                return []
            try:
                data = r.json()
            except Exception:
                return []
            return data if isinstance(data, list) else []

    base_cases = SERVICE_MAP["cases"].rstrip("/")
    base_alerts = SERVICE_MAP["alerts"].rstrip("/")
    base_obs = SERVICE_MAP["observables"].rstrip("/")
    cases_raw, alerts_raw, obs_raw = await asyncio.gather(
        _get_json(f"{base_cases}/cases"),
        _get_json(f"{base_alerts}/alerts"),
        _get_json(f"{base_obs}/observables"),
    )

    case_hits: list[dict[str, Any]] = []
    for c in cases_raw:
        if len(case_hits) >= cap:
            break
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id", ""))
        title = str(c.get("title", ""))
        desc = str(c.get("description", ""))
        tags = " ".join(str(t) for t in (c.get("tags") or []))
        comm = " ".join(
            f"{x.get('author', '')} {x.get('text', '')}" for x in (c.get("comments") or []) if isinstance(x, dict)
        )
        ev_names = " ".join(str(e.get("filename", "")) for e in (c.get("evidence") or []) if isinstance(e, dict))
        blob = f"{title} {desc} {tags} {comm} {ev_names}"
        if _search_match(blob, qn) or _search_match(cid, qn):
            case_hits.append(
                {
                    "kind": "case",
                    "id": cid,
                    "title": title or cid,
                    "subtitle": (desc[:120] + "…") if len(desc) > 120 else desc,
                }
            )

    alert_hits: list[dict[str, Any]] = []
    for a in alerts_raw:
        if len(alert_hits) >= cap:
            break
        if not isinstance(a, dict):
            continue
        aid = str(a.get("id", ""))
        title = str(a.get("title", ""))
        desc = str(a.get("description", ""))
        tags = " ".join(str(t) for t in (a.get("tags") or []))
        obs = " ".join(f"{o.get('type', '')}:{o.get('value', '')}" for o in (a.get("observables") or []) if isinstance(o, dict))
        blob = f"{title} {desc} {tags} {obs}"
        if _search_match(blob, qn) or _search_match(aid, qn):
            alert_hits.append(
                {
                    "kind": "alert",
                    "id": aid,
                    "title": title or aid,
                    "subtitle": str(a.get("source", "")) or (desc[:100] + "…") if len(desc) > 100 else desc,
                }
            )

    obs_hits: list[dict[str, Any]] = []
    for o in obs_raw:
        if len(obs_hits) >= cap:
            break
        if not isinstance(o, dict):
            continue
        val = str(o.get("value", ""))
        oid = str(o.get("id", val))
        typ = str(o.get("type", ""))
        if _search_match(val, qn) or _search_match(typ, qn) or _search_match(oid, qn):
            obs_hits.append({"kind": "observable", "id": oid, "title": f"{typ}: {val}", "subtitle": val})

    return {"query": qn, "cases": case_hits[:cap], "alerts": alert_hits[:cap], "observables": obs_hits[:cap]}


def _soc_risk_score(a: dict[str, Any]) -> int:
    if isinstance(a.get("risk_score"), int):
        return int(a["risk_score"])
    sev = str(a.get("severity", "")).lower()
    base = {"low": 18, "medium": 42, "high": 68, "critical": 92}.get(sev, 38)
    obs = a.get("observables") or []
    n_obs = len(obs) if isinstance(obs, list) else 0
    tags = a.get("tags") or []
    n_tags = len(tags) if isinstance(tags, list) else 0
    bonus = min(28, n_obs * 4 + min(8, n_tags * 2))
    return min(100, base + bonus)


@app.get("/soc/summary")
async def soc_summary(request: Request):
    """Aggregated operational metrics for SOC dashboards (alerts + cases)."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization required")
    claims = _decode_token(auth.split(" ", 1)[1])
    _require_role(claims, {"analyst", "responder", "admin", "readonly"})
    headers: dict[str, str] = {}
    if INTERNAL_SERVICE_TOKEN:
        headers["x-internal-token"] = INTERNAL_SERVICE_TOKEN
    base_cases = SERVICE_MAP["cases"].rstrip("/")
    base_alerts = SERVICE_MAP["alerts"].rstrip("/")
    async with httpx.AsyncClient(timeout=60) as client:
        ra, rc = await asyncio.gather(
            client.get(f"{base_alerts}/alerts", headers=headers),
            client.get(f"{base_cases}/cases", headers=headers),
        )
    alerts: list[Any] = []
    cases: list[Any] = []
    if ra.status_code == 200:
        try:
            data = ra.json()
            if isinstance(data, list):
                alerts = data
        except Exception:
            pass
    if rc.status_code == 200:
        try:
            data = rc.json()
            if isinstance(data, list):
                cases = data
        except Exception:
            pass

    alerts_open = 0
    alerts_critical = 0
    risk_sum = 0
    by_source: dict[str, int] = {}
    for a in alerts:
        if not isinstance(a, dict):
            continue
        st = str(a.get("status", "")).lower()
        if st != "closed":
            alerts_open += 1
        if str(a.get("severity", "")).lower() == "critical":
            alerts_critical += 1
        risk_sum += _soc_risk_score(a)
        src = str(a.get("source") or "unknown")
        by_source[src] = by_source.get(src, 0) + 1
    n_alerts = len(alerts)
    avg_risk = round(risk_sum / n_alerts, 1) if n_alerts else 0.0

    cases_open = 0
    legal_holds = 0
    mttr_samples: list[float] = []
    by_category: dict[str, int] = {}
    for c in cases:
        if not isinstance(c, dict):
            continue
        st = str(c.get("status", "")).lower()
        if st not in {"resolved", "closed"}:
            cases_open += 1
        if c.get("legal_hold"):
            legal_holds += 1
        cat = c.get("incident_category")
        if cat:
            ck = str(cat)
            by_category[ck] = by_category.get(ck, 0) + 1
        if st in {"resolved", "closed"}:
            ca = c.get("created_at")
            ua = c.get("updated_at")
            if ca and ua:
                try:
                    t0 = datetime.fromisoformat(str(ca).replace("Z", "+00:00")).timestamp()
                    t1 = datetime.fromisoformat(str(ua).replace("Z", "+00:00")).timestamp()
                    mttr_samples.append(max(0.0, (t1 - t0) / 3600.0))
                except Exception:
                    pass
    mttr_hours = round(sum(mttr_samples) / len(mttr_samples), 2) if mttr_samples else None

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "alerts": {
            "total": n_alerts,
            "open": alerts_open,
            "critical": alerts_critical,
            "avg_risk_score": avg_risk,
            "by_source": by_source,
        },
        "cases": {
            "total": len(cases),
            "open": cases_open,
            "legal_hold": legal_holds,
            "mttr_resolved_hours": mttr_hours,
            "incident_categories": by_category,
        },
    }


def _soc_auth_claims_and_user(request: Request) -> tuple[dict, str]:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization required")
    claims = _decode_token(auth.split(" ", 1)[1])
    _require_role(claims, {"analyst", "responder", "admin", "readonly"})
    user = str(claims.get("preferred_username") or claims.get("sub") or "").strip() or "user"
    return claims, user


def _soc_auth_user(request: Request) -> str:
    _, user = _soc_auth_claims_and_user(request)
    return user


def _upstream_headers() -> dict[str, str]:
    h: dict[str, str] = {}
    if INTERNAL_SERVICE_TOKEN:
        h["x-internal-token"] = INTERNAL_SERVICE_TOKEN
    return h


def _require_internal_token(request: Request) -> None:
    if not INTERNAL_SERVICE_TOKEN.strip():
        if ALLOW_INSECURE_NO_INTERNAL_TOKEN:
            return
        raise HTTPException(status_code=503, detail="INTERNAL_SERVICE_TOKEN is not configured")
    if request.headers.get("x-internal-token") != INTERNAL_SERVICE_TOKEN:
        raise HTTPException(status_code=401, detail="Internal service authentication required")


async def _investigation_graph_payload(
    client: httpx.AsyncClient,
    *,
    case_id: str | None = None,
    alert_id: str | None = None,
) -> dict[str, Any]:
    ih = _upstream_headers()
    base_c = SERVICE_MAP["cases"].rstrip("/")
    base_a = SERVICE_MAP["alerts"].rstrip("/")
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def add_obs_nodes(container_id: str, observables: Any, rel: str) -> None:
        if not isinstance(observables, list):
            return
        for ob in observables:
            if not isinstance(ob, dict):
                continue
            ov = str(ob.get("value") or "")[:96]
            ot = str(ob.get("type") or "?")
            oid = f"obs:{ot}:{ov}"
            if not any(n["id"] == oid for n in nodes):
                nodes.append({"id": oid, "kind": "observable", "label": f"{ot}:{ov}"[:80]})
            edges.append({"from": container_id, "to": oid, "rel": rel})

    if case_id:
        cr = await client.get(f"{base_c}/cases/{case_id}", headers=ih)
        if cr.status_code != 200:
            raise HTTPException(status_code=cr.status_code, detail="Case not found upstream")
        case = cr.json()
        if not isinstance(case, dict):
            raise HTTPException(status_code=502, detail="Invalid case payload")
        cid = f"case:{case['id']}"
        nodes.append({"id": cid, "kind": "case", "label": str(case.get("title") or case_id)[:80]})
        aid = case.get("alert_id")
        if aid:
            ar = await client.get(f"{base_a}/alerts/{aid}", headers=ih)
            if ar.status_code == 200 and isinstance(ar.json(), dict):
                alert = ar.json()
                nid = f"alert:{aid}"
                nodes.append({"id": nid, "kind": "alert", "label": str(alert.get("title") or aid)[:80]})
                edges.append({"from": cid, "to": nid, "rel": "source_alert"})
                add_obs_nodes(nid, alert.get("observables"), "has_observable")
        add_obs_nodes(cid, case.get("observables"), "case_observable")
        for lk in case.get("linked_case_ids") or []:
            lid = str(lk)
            lr = await client.get(f"{base_c}/cases/{lid}", headers=ih)
            title = lid[:12] + "…"
            if lr.status_code == 200 and isinstance(lr.json(), dict):
                title = str(lr.json().get("title") or lid)[:80]
            node_id = f"case:{lid}"
            nodes.append({"id": node_id, "kind": "case", "label": title})
            edges.append({"from": cid, "to": node_id, "rel": "linked_case"})

    elif alert_id:
        ar = await client.get(f"{base_a}/alerts/{alert_id}", headers=ih)
        if ar.status_code != 200:
            raise HTTPException(status_code=ar.status_code, detail="Alert not found upstream")
        alert = ar.json()
        if not isinstance(alert, dict):
            raise HTTPException(status_code=502, detail="Invalid alert payload")
        nid = f"alert:{alert_id}"
        nodes.append({"id": nid, "kind": "alert", "label": str(alert.get("title") or alert_id)[:80]})
        add_obs_nodes(nid, alert.get("observables"), "has_observable")
        cr_all = await client.get(f"{base_c}/cases", headers=ih)
        if cr_all.status_code == 200 and isinstance(cr_all.json(), list):
            for c in cr_all.json():
                if not isinstance(c, dict):
                    continue
                if str(c.get("alert_id")) != str(alert_id):
                    continue
                cid = f"case:{c['id']}"
                nodes.append({"id": cid, "kind": "case", "label": str(c.get("title") or c["id"])[:80]})
                edges.append({"from": nid, "to": cid, "rel": "escalated_to"})

    return {
        "nodes": nodes,
        "edges": edges,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@app.get("/soc/hunting/queries")
async def list_saved_hunts(request: Request):
    """Per-user saved hunt queries (persisted in gateway Postgres)."""
    user = _soc_auth_user(request)
    pool = await _get_pool()
    rows = await pool.fetch(
        "SELECT id, label, query, created_at FROM sirp_saved_hunts WHERE owner_username = $1 "
        "ORDER BY created_at DESC LIMIT 100",
        user,
    )
    return [
        {
            "id": r["id"],
            "label": r["label"],
            "query": r["query"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]


@app.post("/soc/hunting/queries")
async def create_saved_hunt(request: Request):
    claims, user = _soc_auth_claims_and_user(request)
    if not _require_role_soft(claims, {"analyst", "responder", "admin"}):
        raise HTTPException(status_code=403, detail="Saving hunts requires analyst role or above")
    try:
        body = await request.json()
    except Exception:
        body = {}
    label = str((body or {}).get("label") or "").strip()[:200]
    query = str((body or {}).get("query") or "").strip()[:2000]
    if len(query) < 2:
        raise HTTPException(status_code=400, detail="query must be at least 2 characters")
    if not label:
        label = query[:80]
    hid = str(uuid.uuid4())
    pool = await _get_pool()
    await pool.execute(
        "INSERT INTO sirp_saved_hunts (id, owner_username, label, query) VALUES ($1, $2, $3, $4)",
        hid,
        user,
        label,
        query,
    )
    return {"id": hid, "label": label, "query": query}


@app.delete("/soc/hunting/queries/{hunt_id}")
async def delete_saved_hunt(hunt_id: str, request: Request):
    claims, user = _soc_auth_claims_and_user(request)
    if not _require_role_soft(claims, {"analyst", "responder", "admin"}):
        raise HTTPException(status_code=403, detail="Deleting hunts requires analyst role or above")
    hid = hunt_id.strip()
    if not hid or len(hid) > 80:
        raise HTTPException(status_code=400, detail="Invalid hunt id")
    pool = await _get_pool()
    result = await pool.execute("DELETE FROM sirp_saved_hunts WHERE id = $1 AND owner_username = $2", hid, user)
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Saved hunt not found")
    return {"status": "deleted", "id": hid}


async def _maybe_record_ops_snapshot(pool: asyncpg.Pool, out: dict[str, Any]) -> None:
    """Append throttled ops snapshots for uptime-style history (max ~1 / 3 min)."""
    try:
        last = await pool.fetchval("SELECT max(created_at) FROM sirp_ops_snapshots")
        now = datetime.now(timezone.utc)
        if last is not None:
            lu = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
            if (now - lu).total_seconds() < 180:
                return
        await pool.execute(
            "INSERT INTO sirp_ops_snapshots (snapshot) VALUES ($1::jsonb)",
            json.dumps(out),
        )
        await pool.execute(
            """
            DELETE FROM sirp_ops_snapshots a
            USING (
                SELECT id FROM sirp_ops_snapshots ORDER BY created_at DESC OFFSET 400
            ) AS old WHERE a.id = old.id
            """
        )
    except Exception as exc:
        logger.warning("ops snapshot insert/trim failed: %s", exc)


@app.get("/soc/ops-status")
async def soc_ops_status(request: Request):
    """Reachability of core microservices (for SOC operations wallboard)."""
    _soc_auth_user(request)
    ih: dict[str, str] = {}
    if INTERNAL_SERVICE_TOKEN:
        ih["x-internal-token"] = INTERNAL_SERVICE_TOKEN
    checks: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=6) as client:
        for name, base in SERVICE_MAP.items():
            t0 = time.perf_counter()
            ok = False
            err: str | None = None
            try:
                r = await client.get(f"{base.rstrip('/')}/health", headers=ih)
                ok = r.status_code == 200
            except Exception as exc:
                err = str(exc)[:160]
            checks.append(
                {
                    "service": name,
                    "ok": ok,
                    "ms": round((time.perf_counter() - t0) * 1000, 1),
                    "error": err,
                }
            )
    db_ok = True
    pool = await _get_pool()
    try:
        await pool.fetchval("SELECT 1")
    except Exception:
        db_ok = False
    out: dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "gateway_database": {"ok": db_ok},
        "services": checks,
    }
    await _maybe_record_ops_snapshot(pool, out)
    return out


@app.get("/soc/ops-history")
async def soc_ops_history(request: Request, limit: int = 40):
    """Recent recorded ops-status snapshots (same auth as ops-status)."""
    _soc_auth_user(request)
    lim = max(1, min(int(limit), 200))
    pool = await _get_pool()
    rows = await pool.fetch(
        "SELECT id, created_at, snapshot FROM sirp_ops_snapshots ORDER BY created_at DESC LIMIT $1",
        lim,
    )
    items: list[dict[str, Any]] = []
    for r in rows:
        snap = r["snapshot"]
        if isinstance(snap, str):
            try:
                snap = json.loads(snap)
            except Exception:
                snap = {}
        items.append(
            {
                "id": r["id"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "snapshot": snap if isinstance(snap, dict) else {},
            }
        )
    return {"items": items}


@app.get("/soc/notification-delivery-status")
async def soc_notification_delivery_status(request: Request):
    """Which outbound notification channels have secrets configured (keys only, no values)."""
    _soc_auth_user(request)
    base = SERVICE_MAP["secrets"].rstrip("/")
    headers: dict[str, str] = {}
    if INTERNAL_SERVICE_TOKEN:
        headers["x-internal-token"] = INTERNAL_SERVICE_TOKEN
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.get(f"{base}/secrets", headers=headers)
        except Exception as exc:
            return {"ok": False, "error": str(exc)[:120], "channels": {}}
    if r.status_code != 200:
        return {"ok": False, "error": f"secrets_http_{r.status_code}", "channels": {}}
    try:
        rows = r.json()
    except Exception:
        rows = []
    keyset: set[str] = set()
    if isinstance(rows, list):
        for x in rows:
            if isinstance(x, dict) and x.get("key"):
                keyset.add(str(x["key"]))
    need_email = {"SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "NOTIFY_EMAIL_TO"}
    channels = {
        "email": {"configured": bool(need_email <= keyset)},
        "slack": {"configured": "SLACK_WEBHOOK_URL" in keyset},
        "discord": {"configured": "DISCORD_WEBHOOK_URL" in keyset},
    }
    return {"ok": True, "channels": channels}


@app.post("/soc/internal/mentions/ingest")
async def soc_internal_mentions_ingest(request: Request):
    _require_internal_token(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    case_id = str((body or {}).get("case_id") or "").strip()[:80]
    comment_id = str((body or {}).get("comment_id") or "").strip()[:80]
    author = str((body or {}).get("author") or "").strip()[:200]
    excerpt = str((body or {}).get("excerpt") or "").strip()[:800]
    title = str((body or {}).get("case_title") or "").strip()[:300]
    users = (body or {}).get("mentioned_users") or []
    if not isinstance(users, list):
        users = []
    users = [str(u).strip()[:80] for u in users if str(u).strip()][:40]
    if not case_id or not comment_id or not users:
        raise HTTPException(status_code=400, detail="case_id, comment_id, mentioned_users required")
    pool = await _get_pool()
    for u in users:
        await pool.execute(
            "INSERT INTO sirp_mention_events(case_id, comment_id, author, mentioned_username, excerpt) "
            "VALUES($1,$2,$3,$4,$5) ON CONFLICT (case_id, comment_id, mentioned_username) DO NOTHING",
            case_id,
            comment_id,
            author,
            u,
            excerpt,
        )
    base_n = SERVICE_MAP["notifications"].rstrip("/")
    ih = _upstream_headers()
    async with httpx.AsyncClient(timeout=15) as client:
        await client.post(
            f"{base_n}/notifications/mentions",
            headers=ih,
            json={
                "mentioned_users": users,
                "case_id": case_id,
                "author": author,
                "excerpt": excerpt,
                "case_title": title,
                "comment_id": comment_id,
            },
        )
    return {"status": "ingested", "count": len(users)}


@app.post("/soc/internal/watchers/notify")
async def soc_internal_watchers_notify(request: Request):
    _require_internal_token(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    case_id = str((body or {}).get("case_id") or "").strip()[:80]
    event = str((body or {}).get("event") or "update").strip()[:80]
    summary = str((body or {}).get("summary") or "").strip()[:500]
    actor = str((body or {}).get("actor") or "").strip()[:200]
    if not case_id:
        raise HTTPException(status_code=400, detail="case_id required")
    pool = await _get_pool()
    rows = await pool.fetch("SELECT username FROM sirp_case_watchers WHERE case_id = $1", case_id)
    if not rows:
        return {"notified": 0}
    watchers = [r["username"] for r in rows]
    line = (
        f"SIRP case watch · {case_id}\nEvent: {event}\nActor: {actor}\nWatchers: {', '.join(watchers)}\n{summary}"
    )
    base_n = SERVICE_MAP["notifications"].rstrip("/")
    ih = _upstream_headers()
    wid = f"watch-{uuid.uuid4().hex[:16]}"
    async with httpx.AsyncClient(timeout=15) as client:
        await client.post(
            f"{base_n}/notifications/mentions",
            headers=ih,
            json={
                "mentioned_users": watchers,
                "case_id": case_id,
                "author": "system",
                "excerpt": line[:800],
                "case_title": f"watcher ping: {event}",
                "comment_id": wid,
            },
        )
    return {"notified": len(watchers)}


@app.get("/soc/mentions/for-me")
async def soc_mentions_for_me(request: Request, limit: int = 50):
    _, user = _soc_auth_claims_and_user(request)
    lim = max(1, min(int(limit), 100))
    pool = await _get_pool()
    rows = await pool.fetch(
        "SELECT id, at, case_id, comment_id, author, mentioned_username, excerpt FROM sirp_mention_events "
        "WHERE lower(mentioned_username) = lower($1) ORDER BY at DESC LIMIT $2",
        user,
        lim,
    )
    return {
        "items": [
            {
                "id": r["id"],
                "at": r["at"].isoformat() if r["at"] else None,
                "case_id": r["case_id"],
                "comment_id": r["comment_id"],
                "author": r["author"],
                "mentioned_username": r["mentioned_username"],
                "excerpt": r["excerpt"],
            }
            for r in rows
        ]
    }


async def _graph_upsert_edges(pool: asyncpg.Pool, edges: list[tuple[str, str, str, str, str]]) -> None:
    for sk, sid, dk, did, rel in edges:
        await pool.execute(
            "INSERT INTO sirp_entity_edges(src_kind, src_id, dst_kind, dst_id, rel) VALUES($1,$2,$3,$4,$5) "
            "ON CONFLICT (src_kind, src_id, dst_kind, dst_id, rel) DO UPDATE SET updated_at = now()",
            sk[:32],
            sid[:120],
            dk[:32],
            did[:120],
            rel[:64],
        )


@app.post("/soc/graph/reindex")
async def soc_graph_reindex(request: Request):
    if INTERNAL_SERVICE_TOKEN and request.headers.get("x-internal-token") == INTERNAL_SERVICE_TOKEN:
        actor = "internal"
    else:
        claims, actor = _soc_auth_claims_and_user(request)
        if not _require_role_soft(claims, {"admin"}):
            raise HTTPException(status_code=403, detail="Graph reindex requires admin (or internal token)")
    ih = _upstream_headers()
    base_c = SERVICE_MAP["cases"].rstrip("/")
    base_a = SERVICE_MAP["alerts"].rstrip("/")
    pool = await _get_pool()
    edges_batch: list[tuple[str, str, str, str, str]] = []
    async with httpx.AsyncClient(timeout=120) as client:
        rc = await client.get(f"{base_c}/cases", headers=ih)
        ra = await client.get(f"{base_a}/alerts", headers=ih)
    cases: list[Any] = []
    if rc.status_code == 200:
        try:
            d = rc.json()
            if isinstance(d, list):
                cases = d
        except Exception:
            pass
    alerts: list[Any] = []
    if ra.status_code == 200:
        try:
            d = ra.json()
            if isinstance(d, list):
                alerts = d
        except Exception:
            pass
    for c in cases:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id") or "")
        if not cid:
            continue
        ck, cnode = "case", cid
        aid = c.get("alert_id")
        if aid:
            edges_batch.append((ck, cnode, "alert", str(aid), "source_alert"))
        for ob in c.get("observables") or []:
            if not isinstance(ob, dict) or not ob.get("value"):
                continue
            oid = f"{ob.get('type', '?')}:{str(ob.get('value'))[:200]}"
            edges_batch.append((ck, cnode, "observable", oid, "case_observable"))
        for lk in c.get("linked_case_ids") or []:
            edges_batch.append((ck, cnode, "case", str(lk), "linked_case"))
    for a in alerts:
        if not isinstance(a, dict):
            continue
        aid = str(a.get("id") or "")
        if not aid:
            continue
        nk, nnode = "alert", aid
        for ob in a.get("observables") or []:
            if not isinstance(ob, dict) or not ob.get("value"):
                continue
            oid = f"{ob.get('type', '?')}:{str(ob.get('value'))[:200]}"
            edges_batch.append((nk, nnode, "observable", oid, "has_observable"))
    for edge in edges_batch:
        await _graph_upsert_edges(pool, [edge])
    n = len(edges_batch)
    logger.info("graph reindex by %s: %d edges from %d cases %d alerts", actor, n, len(cases), len(alerts))
    return {"status": "ok", "edges_upserted": n, "cases": len(cases), "alerts": len(alerts)}


@app.get("/soc/graph/neighbors")
async def soc_graph_neighbors(request: Request, focus_kind: str, focus_id: str, limit: int = 200):
    _soc_auth_user(request)
    fk = focus_kind.strip().lower()[:32]
    fid = focus_id.strip()[:120]
    if not fk or not fid:
        raise HTTPException(status_code=400, detail="focus_kind and focus_id required")
    lim = max(1, min(int(limit), 500))
    pool = await _get_pool()
    rows = await pool.fetch(
        "SELECT src_kind, src_id, dst_kind, dst_id, rel FROM sirp_entity_edges "
        "WHERE (src_kind = $1 AND src_id = $2) OR (dst_kind = $1 AND dst_id = $2) LIMIT $3",
        fk,
        fid,
        lim,
    )
    nodes: dict[str, dict[str, str]] = {}
    edges_out: list[dict[str, str]] = []

    def nid(k: str, i: str) -> str:
        return f"{k}:{i}"

    seed = nid(fk, fid)
    nodes[seed] = {"id": seed, "kind": fk, "label": fid[:40]}
    for r in rows:
        sk, si, dk, di = r["src_kind"], r["src_id"], r["dst_kind"], r["dst_id"]
        rel = str(r["rel"] or "")
        s = nid(sk, si)
        d = nid(dk, di)
        nodes.setdefault(s, {"id": s, "kind": sk, "label": si[:60]})
        nodes.setdefault(d, {"id": d, "kind": dk, "label": di[:60]})
        edges_out.append({"from": s, "to": d, "rel": rel})
    return {
        "focus": {"kind": fk, "id": fid},
        "nodes": list(nodes.values()),
        "edges": edges_out,
        "source": "sirp_entity_edges",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@app.get("/soc/retro-hunt/siem")
async def soc_retro_hunt_siem(request: Request, q: str, size: int = 40, index: str | None = None):
    _soc_auth_user(request)
    if len(q.strip()) < 2:
        raise HTTPException(status_code=400, detail="q must be at least 2 characters")
    ih = _upstream_headers()
    base_a = SERVICE_MAP["alerts"].rstrip("/")
    params: dict[str, Any] = {"q": q.strip(), "size": max(1, min(int(size), 100))}
    if index and index.strip():
        params["index"] = index.strip()
    async with httpx.AsyncClient(timeout=45) as client:
        r = await client.get(f"{base_a}/alerts/siem-retro-search", headers=ih, params=params)
    if r.status_code != 200:
        try:
            detail = r.json()
        except Exception:
            detail = r.text[:200]
        raise HTTPException(status_code=502, detail=str(detail)[:300])
    return r.json()


@app.post("/soc/custody-log")
async def soc_custody_log(request: Request):
    claims, user = _soc_auth_claims_and_user(request)
    if not _require_role_soft(claims, {"analyst", "responder", "admin"}):
        raise HTTPException(status_code=403, detail="Custody logging requires analyst role or above")
    try:
        body = await request.json()
    except Exception:
        body = {}
    action = str((body or {}).get("action") or "").strip()[:120]
    if not action:
        raise HTTPException(status_code=400, detail="action is required")
    case_id = (body or {}).get("case_id")
    case_id_s = str(case_id).strip()[:80] if case_id else None
    evidence_id = (body or {}).get("evidence_id")
    ev_s = str(evidence_id).strip()[:80] if evidence_id else None
    detail = (body or {}).get("detail") if isinstance((body or {}).get("detail"), dict) else {}
    pool = await _get_pool()
    await pool.execute(
        "INSERT INTO sirp_chain_of_custody(actor, action, case_id, evidence_id, detail) VALUES($1,$2,$3,$4,$5::jsonb)",
        user,
        action,
        case_id_s,
        ev_s,
        json.dumps(detail),
    )
    return {"status": "logged"}


@app.get("/soc/custody-log")
async def soc_custody_log_list(request: Request, case_id: str | None = None, limit: int = 50):
    _soc_auth_user(request)
    lim = max(1, min(int(limit), 200))
    pool = await _get_pool()
    if case_id and case_id.strip():
        rows = await pool.fetch(
            "SELECT id, at, actor, action, case_id, evidence_id, detail FROM sirp_chain_of_custody "
            "WHERE case_id = $1 ORDER BY at DESC LIMIT $2",
            case_id.strip(),
            lim,
        )
    else:
        rows = await pool.fetch(
            "SELECT id, at, actor, action, case_id, evidence_id, detail FROM sirp_chain_of_custody "
            "ORDER BY at DESC LIMIT $1",
            lim,
        )
    return {
        "items": [
            {
                "id": r["id"],
                "at": r["at"].isoformat() if r["at"] else None,
                "actor": r["actor"],
                "action": r["action"],
                "case_id": r["case_id"],
                "evidence_id": r["evidence_id"],
                "detail": r["detail"],
            }
            for r in rows
        ]
    }


@app.post("/soc/shift-report")
async def soc_shift_report_create(request: Request):
    claims, user = _soc_auth_claims_and_user(request)
    if not _require_role_soft(claims, {"analyst", "responder", "admin"}):
        raise HTTPException(status_code=403, detail="Shift reports require analyst role or above")
    try:
        body = await request.json()
    except Exception:
        body = {}
    summary = str((body or {}).get("summary") or "").strip()
    if len(summary) < 3:
        raise HTTPException(status_code=400, detail="summary must be at least 3 characters")
    case_ids = (body or {}).get("case_ids") or []
    alert_ids = (body or {}).get("alert_ids") or []
    if not isinstance(case_ids, list):
        case_ids = []
    if not isinstance(alert_ids, list):
        alert_ids = []
    case_ids = [str(x)[:80] for x in case_ids[:200]]
    alert_ids = [str(x)[:80] for x in alert_ids[:200]]
    rid = uuid.uuid4()
    pool = await _get_pool()
    await pool.execute(
        "INSERT INTO sirp_shift_reports(id, author, summary, case_refs, alert_refs) VALUES($1,$2,$3,$4::jsonb,$5::jsonb)",
        rid,
        user,
        summary[:8000],
        json.dumps(case_ids),
        json.dumps(alert_ids),
    )
    return {"id": str(rid), "status": "created"}


@app.get("/soc/shift-reports")
async def soc_shift_reports_list(request: Request, limit: int = 40):
    _soc_auth_user(request)
    lim = max(1, min(int(limit), 100))
    pool = await _get_pool()
    rows = await pool.fetch(
        "SELECT id, author, summary, case_refs, alert_refs, created_at FROM sirp_shift_reports "
        "ORDER BY created_at DESC LIMIT $1",
        lim,
    )
    return {
        "items": [
            {
                "id": str(r["id"]),
                "author": r["author"],
                "summary": r["summary"],
                "case_ids": r["case_refs"],
                "alert_ids": r["alert_refs"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


@app.post("/soc/watchlist")
async def soc_watchlist_add(request: Request):
    claims, user = _soc_auth_claims_and_user(request)
    if not _require_role_soft(claims, {"analyst", "responder", "admin"}):
        raise HTTPException(status_code=403, detail="Watchlist requires analyst role or above")
    try:
        body = await request.json()
    except Exception:
        body = {}
    cid = str((body or {}).get("case_id") or "").strip()
    if not cid or len(cid) > 80:
        raise HTTPException(status_code=400, detail="case_id required")
    pool = await _get_pool()
    await pool.execute(
        "INSERT INTO sirp_case_watchers(case_id, username) VALUES($1, $2) ON CONFLICT DO NOTHING",
        cid,
        user,
    )
    return {"status": "watching", "case_id": cid}


@app.delete("/soc/watchlist/{case_id:path}")
async def soc_watchlist_remove(case_id: str, request: Request):
    claims, user = _soc_auth_claims_and_user(request)
    if not _require_role_soft(claims, {"analyst", "responder", "admin"}):
        raise HTTPException(status_code=403, detail="Watchlist requires analyst role or above")
    cid = case_id.strip()[:80]
    if not cid:
        raise HTTPException(status_code=400, detail="Invalid case_id")
    pool = await _get_pool()
    await pool.execute("DELETE FROM sirp_case_watchers WHERE case_id = $1 AND username = $2", cid, user)
    return {"status": "removed", "case_id": cid}


@app.get("/soc/watchlist")
async def soc_watchlist_list(request: Request):
    _, user = _soc_auth_claims_and_user(request)
    pool = await _get_pool()
    rows = await pool.fetch(
        "SELECT case_id, created_at FROM sirp_case_watchers WHERE username = $1 ORDER BY created_at DESC",
        user,
    )
    return {
        "items": [
            {"case_id": r["case_id"], "created_at": r["created_at"].isoformat() if r["created_at"] else None}
            for r in rows
        ]
    }


@app.post("/soc/playbook-run-requests")
async def soc_playbook_run_request_create(request: Request):
    claims, user = _soc_auth_claims_and_user(request)
    if not _require_role_soft(claims, {"analyst", "responder", "admin"}):
        raise HTTPException(status_code=403, detail="Playbook requests require analyst role or above")
    try:
        body = await request.json()
    except Exception:
        body = {}
    pb_id = str((body or {}).get("playbook_id") or "").strip()
    if not pb_id or len(pb_id) > 120:
        raise HTTPException(status_code=400, detail="playbook_id required")
    case_id = (body or {}).get("case_id")
    case_s = str(case_id).strip()[:80] if case_id else None
    ev = (body or {}).get("event")
    ev_json: dict[str, Any] = ev if isinstance(ev, dict) else {}
    chain_raw = (body or {}).get("approval_chain")
    chain_json: str | None = None
    if isinstance(chain_raw, list) and chain_raw:
        clean: list[dict[str, str]] = []
        for step in chain_raw[:8]:
            if isinstance(step, dict) and str(step.get("role") or "").strip() in VALID_ROLES:
                clean.append({"role": str(step["role"]).strip()})
        if clean:
            chain_json = json.dumps(clean)
    rid = uuid.uuid4()
    pool = await _get_pool()
    await pool.execute(
        "INSERT INTO sirp_playbook_run_requests(id, playbook_id, requester, case_id, event_payload, status, "
        "approval_chain, current_step, step_approvals) "
        "VALUES($1,$2,$3,$4,$5::jsonb,'pending',$6::jsonb,0,'[]'::jsonb)",
        rid,
        pb_id,
        user,
        case_s,
        json.dumps(ev_json),
        chain_json,
    )
    return {"id": str(rid), "status": "pending"}


@app.get("/soc/playbook-run-requests")
async def soc_playbook_run_requests_list(request: Request, status: str | None = None, limit: int = 50):
    _soc_auth_user(request)
    lim = max(1, min(int(limit), 100))
    pool = await _get_pool()
    st = (status or "").strip().lower()
    if st in {"pending", "approved", "rejected"}:
        rows = await pool.fetch(
            "SELECT id, playbook_id, requester, case_id, event_payload, status, approver, resolution_note, "
            "created_at, resolved_at, approval_chain, current_step, step_approvals "
            "FROM sirp_playbook_run_requests WHERE status = $1 "
            "ORDER BY created_at DESC LIMIT $2",
            st,
            lim,
        )
    else:
        rows = await pool.fetch(
            "SELECT id, playbook_id, requester, case_id, event_payload, status, approver, resolution_note, "
            "created_at, resolved_at, approval_chain, current_step, step_approvals "
            "FROM sirp_playbook_run_requests ORDER BY created_at DESC LIMIT $1",
            lim,
        )
    return {
        "items": [
            {
                "id": str(r["id"]),
                "playbook_id": r["playbook_id"],
                "requester": r["requester"],
                "case_id": r["case_id"],
                "event_payload": r["event_payload"],
                "status": r["status"],
                "approver": r["approver"],
                "resolution_note": r["resolution_note"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "resolved_at": r["resolved_at"].isoformat() if r["resolved_at"] else None,
                "approval_chain": r["approval_chain"],
                "current_step": r["current_step"],
                "step_approvals": r["step_approvals"],
            }
            for r in rows
        ]
    }


@app.post("/soc/playbook-run-requests/{req_id}/approve")
async def soc_playbook_run_request_approve(req_id: str, request: Request):
    claims, approver = _soc_auth_claims_and_user(request)
    if not _require_role_soft(claims, {"admin", "responder"}):
        raise HTTPException(status_code=403, detail="Only responder or admin can approve playbook runs")
    try:
        rid = uuid.UUID(req_id.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid request id")
    pool = await _get_pool()
    row = await pool.fetchrow(
        "SELECT playbook_id, case_id, event_payload, status, approval_chain, current_step, step_approvals "
        "FROM sirp_playbook_run_requests WHERE id = $1",
        rid,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Request not found")
    if str(row["status"]) != "pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    payload: dict[str, Any] = {}
    ep = row["event_payload"]
    if isinstance(ep, dict):
        payload = dict(ep)
    elif isinstance(ep, str):
        try:
            payload = dict(json.loads(ep))
        except Exception:
            payload = {}
    if row["case_id"]:
        payload.setdefault("case_id", row["case_id"])

    chain_val = row["approval_chain"]
    chain: list[dict[str, Any]] = []
    if isinstance(chain_val, list):
        chain = [x for x in chain_val if isinstance(x, dict)]
    elif isinstance(chain_val, str):
        try:
            parsed = json.loads(chain_val)
            if isinstance(parsed, list):
                chain = [x for x in parsed if isinstance(x, dict)]
        except Exception:
            chain = []

    step_idx = int(row["current_step"] or 0)
    hist_val = row["step_approvals"]
    step_hist: list[Any] = []
    if isinstance(hist_val, list):
        step_hist = list(hist_val)
    elif isinstance(hist_val, str):
        try:
            parsed = json.loads(hist_val)
            if isinstance(parsed, list):
                step_hist = list(parsed)
        except Exception:
            step_hist = []

    async def _run_automation() -> Any:
        base_auto = SERVICE_MAP["automation"].rstrip("/")
        url = f"{base_auto}/automation/playbooks/{row['playbook_id']}/run"
        ih = _upstream_headers()
        async with httpx.AsyncClient(timeout=120) as client:
            rr = await client.post(url, headers=ih, json=payload)
        if rr.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"Automation run failed: HTTP {rr.status_code}")
        try:
            return rr.json()
        except Exception:
            return {"raw": rr.text[:500]}

    if not chain:
        run_body = await _run_automation()
        await pool.execute(
            "UPDATE sirp_playbook_run_requests SET status = 'approved', approver = $2, resolved_at = now(), "
            "resolution_note = $3 WHERE id = $1",
            rid,
            approver,
            "executed_via_gateway",
        )
        return {"status": "approved", "automation": run_body}

    if step_idx >= len(chain):
        raise HTTPException(status_code=400, detail="Approval chain already completed")
    required_role = str(chain[step_idx].get("role") or "").strip()
    if required_role not in VALID_ROLES or not _require_role_soft(claims, {required_role}):
        raise HTTPException(
            status_code=403,
            detail=f"Step {step_idx + 1}/{len(chain)} requires role: {required_role}",
        )
    step_hist.append(
        {"step": step_idx, "approver": approver, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    )
    step_idx += 1
    if step_idx >= len(chain):
        run_body = await _run_automation()
        await pool.execute(
            "UPDATE sirp_playbook_run_requests SET status = 'approved', approver = $2, resolved_at = now(), "
            "resolution_note = $3, current_step = $4, step_approvals = $5::jsonb WHERE id = $1",
            rid,
            approver,
            "multi_step_executed",
            step_idx,
            json.dumps(step_hist),
        )
        return {"status": "approved", "automation": run_body, "approval_steps": step_hist}

    await pool.execute(
        "UPDATE sirp_playbook_run_requests SET current_step = $2, step_approvals = $3::jsonb WHERE id = $1",
        rid,
        step_idx,
        json.dumps(step_hist),
    )
    return {
        "status": "pending_next_step",
        "current_step": step_idx,
        "total_steps": len(chain),
        "step_approvals": step_hist,
    }


@app.post("/soc/playbook-run-requests/{req_id}/reject")
async def soc_playbook_run_request_reject(req_id: str, request: Request):
    claims, approver = _soc_auth_claims_and_user(request)
    if not _require_role_soft(claims, {"admin", "responder"}):
        raise HTTPException(status_code=403, detail="Only responder or admin can reject playbook runs")
    try:
        rid = uuid.UUID(req_id.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid request id")
    try:
        body = await request.json()
    except Exception:
        body = {}
    note = str((body or {}).get("note") or "").strip()[:500]
    pool = await _get_pool()
    r = await pool.execute(
        "UPDATE sirp_playbook_run_requests SET status = 'rejected', approver = $2, resolved_at = now(), "
        "resolution_note = $3 WHERE id = $1 AND status = 'pending'",
        rid,
        approver,
        note or "rejected",
    )
    if r == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Pending request not found")
    return {"status": "rejected"}


@app.get("/soc/investigation-graph")
async def soc_investigation_graph(request: Request, case_id: str | None = None, alert_id: str | None = None):
    _soc_auth_user(request)
    if not case_id and not alert_id:
        raise HTTPException(status_code=400, detail="Provide case_id or alert_id")
    async with httpx.AsyncClient(timeout=60) as client:
        return await _investigation_graph_payload(
            client,
            case_id=case_id.strip() if case_id else None,
            alert_id=alert_id.strip() if alert_id else None,
        )


@app.get("/soc/investigation-bundle")
async def soc_investigation_bundle(request: Request, case_id: str):
    claims, user = _soc_auth_claims_and_user(request)
    if not _require_role_soft(claims, {"analyst", "responder", "admin"}):
        raise HTTPException(status_code=403, detail="Bundle download requires analyst role or above")
    cid = case_id.strip()
    if not cid:
        raise HTTPException(status_code=400, detail="case_id required")
    ih = _upstream_headers()
    base_c = SERVICE_MAP["cases"].rstrip("/")
    pool = await _get_pool()
    async with httpx.AsyncClient(timeout=90) as client:
        er = await client.get(f"{base_c}/cases/{cid}/export", headers=ih)
        if er.status_code != 200:
            raise HTTPException(status_code=er.status_code, detail="Case export failed upstream")
        export_payload = er.json()
        graph = await _investigation_graph_payload(client, case_id=cid)
    custody_rows = await pool.fetch(
        "SELECT id, at, actor, action, evidence_id, detail FROM sirp_chain_of_custody "
        "WHERE case_id = $1 ORDER BY at DESC LIMIT 40",
        cid,
    )
    custody_out = [
        {
            "id": r["id"],
            "at": r["at"].isoformat() if r["at"] else None,
            "actor": r["actor"],
            "action": r["action"],
            "evidence_id": r["evidence_id"],
            "detail": r["detail"],
        }
        for r in custody_rows
    ]
    await pool.execute(
        "INSERT INTO sirp_chain_of_custody(actor, action, case_id, detail) VALUES($1,$2,$3,$4::jsonb)",
        user,
        "investigation_bundle_download",
        cid,
        json.dumps({"bundle_version": 1}),
    )
    return {
        "bundle_version": 1,
        "assembled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "export": export_payload,
        "graph": graph,
        "custody_recent": custody_out,
    }


@app.get("/soc/analytics-advanced")
async def soc_analytics_advanced(request: Request):
    _soc_auth_user(request)
    ih = _upstream_headers()
    base_cases = SERVICE_MAP["cases"].rstrip("/")
    base_alerts = SERVICE_MAP["alerts"].rstrip("/")
    async with httpx.AsyncClient(timeout=60) as client:
        ra, rc = await asyncio.gather(
            client.get(f"{base_alerts}/alerts", headers=ih),
            client.get(f"{base_cases}/cases", headers=ih),
        )
    alerts: list[Any] = []
    cases: list[Any] = []
    if ra.status_code == 200:
        try:
            data = ra.json()
            if isinstance(data, list):
                alerts = data
        except Exception:
            pass
    if rc.status_code == 200:
        try:
            data = rc.json()
            if isinstance(data, list):
                cases = data
        except Exception:
            pass
    by_status: dict[str, int] = {}
    unassigned_alerts = 0
    for a in alerts:
        if not isinstance(a, dict):
            continue
        st = str(a.get("status") or "unknown").lower()
        by_status[st] = by_status.get(st, 0) + 1
        if not (str(a.get("assigned_to") or "").strip()):
            unassigned_alerts += 1
    unassigned_cases = sum(
        1 for c in cases if isinstance(c, dict) and not (str(c.get("assigned_to") or "").strip())
    )
    n_alerts = len(alerts)
    closed_n = by_status.get("closed", 0)
    noise_proxy = round(100.0 * closed_n / n_alerts, 1) if n_alerts else None
    sev_counts: dict[str, int] = {}
    for a in alerts:
        if not isinstance(a, dict):
            continue
        sv = str(a.get("severity") or "unknown").lower()
        sev_counts[sv] = sev_counts.get(sv, 0) + 1
    case_status: dict[str, int] = {}
    for c in cases:
        if not isinstance(c, dict):
            continue
        st = str(c.get("status") or "unknown").lower()
        case_status[st] = case_status.get(st, 0) + 1
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "alerts": {
            "total": n_alerts,
            "by_status": by_status,
            "by_severity": sev_counts,
            "unassigned": unassigned_alerts,
            "closure_ratio_percent": noise_proxy,
        },
        "cases": {
            "total": len(cases),
            "by_status": case_status,
            "unassigned": unassigned_cases,
        },
    }


@app.get("/soc/retro-hunt")
async def soc_retro_hunt(request: Request, q: str, limit: int = 40):
    _soc_auth_user(request)
    qn = q.strip().lower()
    if len(qn) < 2:
        raise HTTPException(status_code=400, detail="q must be at least 2 characters")
    lim = max(1, min(int(limit), 200))
    base_o = SERVICE_MAP["observables"].rstrip("/")
    ih = _upstream_headers()
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(f"{base_o}/observables", headers=ih)
    obs: list[Any] = []
    if r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list):
                obs = data
        except Exception:
            pass
    hits: list[dict[str, Any]] = []
    for o in obs:
        if not isinstance(o, dict):
            continue
        val = str(o.get("value") or "").lower()
        typ = str(o.get("type") or "").lower()
        if qn in val or qn in typ:
            hits.append(
                {
                    "id": o.get("id"),
                    "type": o.get("type"),
                    "value": o.get("value"),
                    "created_at": o.get("created_at"),
                }
            )
        if len(hits) >= lim:
            break
    return {"query": q, "scanned": len(obs), "matches": hits[:lim]}


@app.get("/soc/enrichment-hints")
async def soc_enrichment_hints(request: Request, alert_id: str):
    _soc_auth_user(request)
    aid = alert_id.strip()
    if not aid:
        raise HTTPException(status_code=400, detail="alert_id required")
    ih = _upstream_headers()
    base_a = SERVICE_MAP["alerts"].rstrip("/")
    async with httpx.AsyncClient(timeout=20) as client:
        ar = await client.get(f"{base_a}/alerts/{aid}", headers=ih)
    if ar.status_code != 200:
        raise HTTPException(status_code=ar.status_code, detail="Alert not found")
    alert = ar.json()
    if not isinstance(alert, dict):
        raise HTTPException(status_code=502, detail="Invalid alert")
    hints: list[dict[str, str]] = []
    for ob in alert.get("observables") or []:
        if not isinstance(ob, dict):
            continue
        t = str(ob.get("type") or "").lower()
        v = str(ob.get("value") or "").strip()
        if not v:
            continue
        if t == "ip" or "." in v and t in {"", "ip", "ipv4"}:
            hints.append(
                {
                    "kind": "abuseipdb_candidate",
                    "ioc_type": t or "ip",
                    "ioc_value": v,
                    "note": "Use Alerts → AbuseIPDB lookup from UI",
                }
            )
        hints.append(
            {
                "kind": "opencti_search",
                "ioc_type": t or "other",
                "ioc_value": v,
                "note": "Pivot via OpenCTI nav or case intel modal",
            }
        )
    return {"alert_id": aid, "hints": hints[:40]}


# ── Inbound SIEM ingest (rate limited; token required unless explicit dev bypass) ─
def _validate_webhook_token(request: Request) -> None:
    provided = request.headers.get("x-webhook-token", "")
    auth = request.headers.get("authorization", "")
    bearer = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else ""
    if INBOUND_WEBHOOK_TOKEN:
        if provided != INBOUND_WEBHOOK_TOKEN and bearer != INBOUND_WEBHOOK_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid webhook token")
        return
    if ALLOW_INGEST_WITHOUT_TOKEN:
        return
    raise HTTPException(
        status_code=503,
        detail="INBOUND_WEBHOOK_TOKEN must be set for ingest (or set ALLOW_INGEST_WITHOUT_TOKEN=1 for dev only)",
    )


@app.post("/ingest/{source}")
@limiter.limit("120/minute")
async def ingest_external(source: str, request: Request):
    if source not in {"wazuh", "splunk", "generic"}:
        raise HTTPException(status_code=400, detail="Unsupported ingest source")

    _validate_webhook_token(request)
    target = SERVICE_MAP["alerts"]
    url = urljoin(f"{target.rstrip('/')}/", f"alerts/webhook/{source}")
    body = await request.body()
    forward_headers = _forward_headers_from_request(request)
    for hk in list(forward_headers.keys()):
        if hk.lower() in ("authorization", "x-webhook-token"):
            del forward_headers[hk]
    # Alert-service allowlist sees the gateway container IP unless we forward the real client (Wazuh).
    client_host = request.client.host if request.client else ""
    if client_host:
        forward_headers["X-SIRP-Ingest-Client-IP"] = client_host
    if INTERNAL_SERVICE_TOKEN:
        forward_headers["x-internal-token"] = INTERNAL_SERVICE_TOKEN

    async with httpx.AsyncClient(timeout=60) as client:
        try:
            resp = await client.request("POST", url, params=request.query_params, content=body, headers=forward_headers)
        except httpx.ConnectError as exc:
            raise HTTPException(status_code=502, detail="Alert service unreachable") from exc
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail="Alert service request failed") from exc
    return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))


# ── WebSocket stream (auth required) ─────────────────────────────────────────
@app.websocket("/stream/events")
async def stream_events(websocket: WebSocket):
    # Validate token before accepting (query param deprecated — prefer Cookie: sirp_token via same-origin WS proxy)
    token = websocket.query_params.get("token") or ""
    if not token:
        auth_header = websocket.headers.get("authorization", "")
        token = auth_header.split(" ", 1)[1] if auth_header.startswith("Bearer ") else ""
    if not token:
        token = (websocket.cookies or {}).get("sirp_token") or ""
    if not token:
        await websocket.close(code=4001, reason="Authorization required")
        return
    try:
        _decode_token(token)
    except Exception:
        await websocket.close(code=4001, reason="Invalid token")
        return

    await websocket.accept()
    consumer = AIOKafkaConsumer(
        "alerts.normalized",
        "cases.updated",
        bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092"),
        group_id=None,
        enable_auto_commit=False,
    )
    await consumer.start()
    try:
        async for msg in consumer:
            await websocket.send_json({
                "topic": msg.topic,
                "partition": msg.partition,
                "offset": msg.offset,
                "payload": msg.value.decode(errors="ignore"),
            })
    except WebSocketDisconnect:
        pass
    finally:
        await consumer.stop()


# ── Proxy ─────────────────────────────────────────────────────────────────────
@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(service: str, path: str, request: Request):
    target = SERVICE_MAP.get(service)
    if not target:
        raise HTTPException(status_code=404, detail="Unknown service")

    auth = request.headers.get("authorization", "")

    # Services that require authentication at all times
    AUTH_REQUIRED = {"secrets", "cases", "automation", "notifications", "alerts", "observables"}

    if service in AUTH_REQUIRED and not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization required")

    claims: dict | None = None
    if auth.startswith("Bearer "):
        claims = _decode_token(auth.split(" ", 1)[1])
        # readonly can read alerts + observables; analyst/responder/admin can mutate
        if service in {"alerts", "observables"}:
            _require_role(claims, {"analyst", "responder", "admin", "readonly"})
            if request.method not in {"GET", "HEAD", "OPTIONS"} and not _require_role_soft(claims, {"analyst", "responder", "admin"}):
                raise HTTPException(status_code=403, detail="Write access requires analyst role or above")
        if service in {"cases", "automation", "notifications"}:
            _require_role(claims, {"analyst", "responder", "admin", "readonly"})
        if service == "secrets":
            _require_role(claims, {"admin"})
        if (
            service == "notifications"
            and request.method == "POST"
            and claims
            and path.rstrip("/") == "notifications/test"
            and not _require_role_soft(claims, {"analyst", "responder", "admin"})
        ):
            raise HTTPException(status_code=403, detail="Test notification requires analyst role or above")

    body = await request.body()
    url = urljoin(f"{target.rstrip('/')}/", path)
    forward_headers = _forward_headers_from_request(request)
    if INTERNAL_SERVICE_TOKEN:
        forward_headers["x-internal-token"] = INTERNAL_SERVICE_TOKEN
    async with httpx.AsyncClient(timeout=60) as client:
        try:
            resp = await client.request(
                request.method, url,
                params=request.query_params, content=body, headers=forward_headers,
            )
        except httpx.ConnectError as exc:
            raise HTTPException(status_code=502, detail=f"Upstream '{service}' unreachable") from exc
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Upstream '{service}' request failed") from exc

    if claims and request.method in ("POST", "PUT", "PATCH", "DELETE") and 200 <= resp.status_code < 400:
        actor = claims.get("preferred_username") or claims.get("sub") or "?"
        rtype, rid = _audit_resource_from_proxy(service, path)
        await _audit_append(
            actor,
            request.method,
            str(request.url.path),
            resp.status_code,
            rtype,
            rid,
            {"upstream": service, "path": path[:400]},
        )

    return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))
