import json
import os
from email.message import EmailMessage

import aiosmtplib
import httpx
from aiokafka import AIOKafkaConsumer
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI(title="Notification Service")
Instrumentator().instrument(app).expose(app)
consumer: AIOKafkaConsumer | None = None
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")
SECRET_SERVICE_URL = os.getenv("SECRET_SERVICE_URL", "http://secret-service:8001")


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


async def _notify_email(subject: str, body: str):
    smtp_host = await _secret_value("SMTP_HOST")
    smtp_user = await _secret_value("SMTP_USER")
    smtp_password = await _secret_value("SMTP_PASSWORD")
    recipient = await _secret_value("NOTIFY_EMAIL_TO")
    if not all([smtp_host, smtp_user, smtp_password, recipient]):
        return

    msg = EmailMessage()
    msg["From"] = smtp_user
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)
    await aiosmtplib.send(
        msg,
        hostname=smtp_host,
        port=int((await _secret_value("SMTP_PORT")) or "587"),
        username=smtp_user,
        password=smtp_password,
        start_tls=True,
    )


async def _notify_webhook(url: str, payload: dict):
    if not url:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(url, json=payload)


async def _dispatch(event: dict):
    summary = f"topic={event.get('topic')} payload={str(event.get('payload'))[:500]}"
    await _notify_email("SIRP Event Notification", summary)
    await _notify_webhook(await _secret_value("SLACK_WEBHOOK_URL"), {"text": summary})
    await _notify_webhook(await _secret_value("DISCORD_WEBHOOK_URL"), {"content": summary})


@app.on_event("startup")
async def startup():
    global consumer
    consumer = AIOKafkaConsumer(
        "cases.updated",
        "analyzers.results",
        bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092"),
        group_id="notification-service",
    )
    await consumer.start()
    import asyncio

    asyncio.create_task(_worker())


@app.on_event("shutdown")
async def shutdown():
    if consumer:
        await consumer.stop()


@app.post("/notifications/test")
async def test_notification(payload: dict):
    await _dispatch({"topic": "manual.test", "payload": payload})
    return {"status": "sent"}


async def _worker():
    assert consumer
    async for msg in consumer:
        try:
            payload = json.loads(msg.value.decode())
        except Exception:
            payload = {"raw": msg.value.decode(errors="ignore")}
        await _dispatch({"topic": msg.topic, "payload": payload})
