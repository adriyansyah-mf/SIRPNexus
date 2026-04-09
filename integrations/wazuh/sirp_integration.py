#!/usr/bin/env python3
"""
Wazuh -> SIRP webhook integration script.

Intended usage:
- Wazuh Integrator (custom-*): argv[1]=alert JSON file, argv[2]=api_key, argv[3]=hook_url
  (see https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
- Standalone: argv[1]=alert file only, URL/token from env; or JSON on stdin for tests.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


INGEST_URL = os.getenv("SIRP_INGEST_URL", "http://localhost:8000/ingest/wazuh").strip()
WEBHOOK_TOKEN = os.getenv("SIRP_WEBHOOK_TOKEN", "").strip()
TIMEOUT_SECONDS = _env_float("SIRP_TIMEOUT_SECONDS", 10.0)
RETRIES = max(1, _env_int("SIRP_RETRIES", 3))
BACKOFF_SECONDS = _env_float("SIRP_RETRY_BACKOFF_SECONDS", 1.5)


def _ensure_ingest_path(base: str) -> str:
    """If hook_url is only scheme://host:port, append /ingest/wazuh for SIRP."""
    base = base.strip()
    if not base:
        return INGEST_URL
    parsed = urlparse(base)
    if parsed.path in ("", "/"):
        return urljoin(base.rstrip("/") + "/", "ingest/wazuh")
    return base


def _resolve_target_url() -> str:
    # Wazuh passes hook_url as argv[3] when using <hook_url> in ossec.conf.
    if len(sys.argv) >= 4 and sys.argv[3].strip():
        return _ensure_ingest_path(sys.argv[3].strip())
    return _ensure_ingest_path(INGEST_URL)


def _resolve_webhook_token() -> str:
    # Wazuh passes <api_key> as argv[2]; SIRP expects the same value in INBOUND_WEBHOOK_TOKEN.
    if len(sys.argv) >= 3 and sys.argv[2].strip():
        return sys.argv[2].strip()
    return WEBHOOK_TOKEN


def _load_payload() -> dict[str, Any]:
    # Wazuh integration passes alert JSON file path as first arg.
    if len(sys.argv) > 1 and sys.argv[1]:
        payload_path = Path(sys.argv[1])
        if not payload_path.exists():
            raise FileNotFoundError(f"Alert payload file not found: {payload_path}")
        return json.loads(payload_path.read_text(encoding="utf-8"))

    # Fallback for manual testing:
    raw = sys.stdin.read().strip()
    if not raw:
        raise ValueError("No JSON payload provided via argument or stdin.")
    return json.loads(raw)


def _post_payload(payload: dict[str, Any], ingest_url: str, webhook_token: str) -> tuple[int, str]:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if webhook_token:
        headers["x-webhook-token"] = webhook_token

    req = urllib.request.Request(ingest_url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        resp_body = resp.read().decode("utf-8", errors="replace")
        return resp.status, resp_body


def main() -> int:
    ingest_url = _resolve_target_url()
    webhook_token = _resolve_webhook_token()

    try:
        payload = _load_payload()
    except Exception as exc:
        print(f"[sirp-wazuh] payload error: {exc}", file=sys.stderr)
        return 1

    last_error: str | None = None
    for attempt in range(1, RETRIES + 1):
        try:
            status, resp_body = _post_payload(payload, ingest_url, webhook_token)
            print(f"[sirp-wazuh] sent to {ingest_url} status={status}")
            if resp_body:
                print(resp_body)
            return 0
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            last_error = f"HTTP {exc.code}: {body or exc.reason}"
            retryable = exc.code >= 500 or exc.code == 429
            if not retryable or attempt >= RETRIES:
                break
        except urllib.error.URLError as exc:
            last_error = f"network error: {exc.reason}"
            if attempt >= RETRIES:
                break
        except Exception as exc:
            last_error = f"unexpected error: {exc}"
            if attempt >= RETRIES:
                break

        sleep_for = BACKOFF_SECONDS * attempt
        time.sleep(sleep_for)

    print(f"[sirp-wazuh] failed after {RETRIES} attempts: {last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

