import asyncio
import json
import logging
import os
import re
import sys
import time
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

AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "sirp-api")
OIDC_ISSUER = os.getenv("KEYCLOAK_ISSUER", "")
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")
INBOUND_WEBHOOK_TOKEN = os.getenv("INBOUND_WEBHOOK_TOKEN", "")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(4 * 1024 * 1024)))  # 4 MB default
# Multipart case evidence uploads (POST …/cases/cases/{id}/evidence)
MAX_CASE_EVIDENCE_BYTES = int(os.getenv("MAX_CASE_EVIDENCE_BYTES", str(32 * 1024 * 1024)))

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


# ── Inbound SIEM ingest (no gateway rate limit; token + alert-service allowlist) ─
def _validate_webhook_token(request: Request) -> None:
    provided = request.headers.get("x-webhook-token", "")
    auth = request.headers.get("authorization", "")
    bearer = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else ""
    if INBOUND_WEBHOOK_TOKEN:
        if provided != INBOUND_WEBHOOK_TOKEN and bearer != INBOUND_WEBHOOK_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid webhook token")
    # If INBOUND_WEBHOOK_TOKEN not set, fall back to allowlist enforced by alert-service


@app.post("/ingest/{source}")
@limiter.exempt
async def ingest_external(source: str, request: Request):
    if source not in {"wazuh", "splunk", "generic"}:
        raise HTTPException(status_code=400, detail="Unsupported ingest source")

    _validate_webhook_token(request)
    target = SERVICE_MAP["alerts"]
    url = urljoin(f"{target.rstrip('/')}/", f"alerts/webhook/{source}")
    body = await request.body()
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower()
        not in {"host", "authorization", "x-webhook-token", "x-sirp-ingest-client-ip"}
    }
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
    # Validate token before accepting
    token = websocket.query_params.get("token") or ""
    if not token:
        auth_header = websocket.headers.get("authorization", "")
        token = auth_header.split(" ", 1)[1] if auth_header.startswith("Bearer ") else ""
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

    body = await request.body()
    url = urljoin(f"{target.rstrip('/')}/", path)
    forward_headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
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
