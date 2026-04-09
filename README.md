# SIRP - Security Incident Response Platform

Production-oriented, event-driven SOC platform inspired by TheHive with real SIEM connectors and OpenCTI for threat intelligence.

## 1) Architecture Diagram

```mermaid
flowchart LR
  SIEM[Wazuh / Elastic SIEM / Splunk / OpenCTI / Generic Webhooks] --> AGW[API Gateway
OIDC + RBAC + rate limiting]
  AGW --> ALS[Alert Service]
  ALS -->|alerts.normalized| K[(Kafka)]
  ALS -->|observables.created| K
  K --> OBS[Observable Service]
  K --> CAS[Case Service]
  K --> AUTO[Automation Service]
  FE[Next.js Frontend] --> AGW
```

## 2) Docker Setup

- `docker-compose.yml` - development stack
- `docker-compose.prod.yml` - production baseline
- Multi-stage Dockerfiles for all services

Included runtime services:

- `api-gateway`
- `keycloak`
- `kafka`, `zookeeper`
- `postgres`
- `elasticsearch`
- `redis`
- `vault`
- `prometheus`, `grafana`, `jaeger`
- `alert-service`, `case-service`, `observable-service`, `automation-service`, `notification-service`, `secret-service`
- `frontend`

## 3) Core Services

- `api-gateway`: OIDC JWT validation, RBAC, routing
- `alert-service`: SIEM connectors, normalization, dedupe, Kafka publishing
- `case-service`: alert-to-case escalation, assignment/ownership
- `observable-service`: IOC dedupe/correlation from `observables.created`
- `automation-service`: SOAR-lite actions
- `frontend`: Next.js SOC dashboard

## Setup

1. Copy environment file:

```bash
cp .env.example .env
```

2. Fill API keys and SIEM credentials in `.env`.
3. Start stack:

```bash
docker compose up -d --build
```

4. Create Kafka topics:

```bash
bash infra/kafka/create-topics.sh
```

5. Open:
   - API Gateway: `http://localhost:8000`
   - Frontend: `http://localhost:3000`
   - Keycloak: `http://localhost:8080`
   - Grafana: `http://localhost:3001`
   - Jaeger: `http://localhost:16686`

6. Login to UI:
   - Open `http://localhost:3000/login`
   - Use credentials from `.env`:
     - `INITIAL_ADMIN_USERNAME`
     - `INITIAL_ADMIN_PASSWORD`
   - JWT is signed with `APP_AUTH_JWT_SECRET`
   - Admin features require `admin` role from this local auth token

## SIEM Integration

### Wazuh

- Pull ingestion endpoint: `POST /alerts/connectors/pull/wazuh`
- External ingest endpoint (recommended): `POST /ingest/wazuh`
- Internal webhook endpoint (service-level): `POST /alerts/alerts/webhook/wazuh`
- Required env: `WAZUH_URL`, `WAZUH_USER`, `WAZUH_PASSWORD`
- Optional ingress auth env: `INBOUND_WEBHOOK_TOKEN` (gateway validates `x-webhook-token` or bearer token)
- Behavior: Authenticates against Wazuh API, fetches events, normalizes, deduplicates, publishes to Kafka.
- Ready integration script: `integrations/wazuh/sirp_integration.py`

### Elastic SIEM

- Pull ingestion endpoint: `POST /alerts/connectors/pull/elastic`
- Required env: `ELASTIC_SIEM_URL`, `ELASTIC_SIEM_API_KEY`, `ELASTIC_SIEM_INDEX`
- Behavior: Queries SIEM index, maps ECS/kibana alert fields to internal schema.

### Splunk

- Pull ingestion endpoint: `POST /alerts/connectors/pull/splunk`
- Webhook ingestion endpoint: `POST /alerts/alerts/webhook/splunk`
- Required env: `SPLUNK_URL`, `SPLUNK_TOKEN`, `SPLUNK_SAVED_SEARCH`
- Behavior: Dispatches saved search job via Splunk REST API and ingests results.

### Microsoft Sentinel

- Pull ingestion endpoint: `POST /alerts/connectors/pull/sentinel`
- Required env:
  - `SENTINEL_TENANT_ID`
  - `SENTINEL_CLIENT_ID`
  - `SENTINEL_CLIENT_SECRET`
  - `SENTINEL_SUBSCRIPTION_ID`
  - `SENTINEL_RESOURCE_GROUP`
  - `SENTINEL_WORKSPACE`
- Behavior: Uses Azure AD client credentials and calls SecurityInsights incidents API on Azure Management endpoint.

### OpenCTI (Threat Intelligence Platform)

- Pull ingestion endpoint: `POST /alerts/connectors/pull/opencti`
- Required env:
  - `OPENCTI_URL`
  - `OPENCTI_TOKEN` (Personal Access Token from OpenCTI user profile — not a connector ID; do not prefix with `Bearer `), or `OPENCTI_API_KEY` as alias, or `OPENCTI_USER` + `OPENCTI_PASSWORD` for GraphQL `token` login
- Optional env:
  - `OPENCTI_QUERY_LIMIT`
  - `OPENCTI_AUTO_SYNC_ENABLED` (`true|false`)
  - `OPENCTI_AUTO_SYNC_INTERVAL_SECONDS`
- Behavior:
  - Pulls real observables from OpenCTI GraphQL API (`stixCyberObservables`)
  - Normalizes to internal alert schema
  - Publishes to Kafka (`alerts.*`, `observables.created`) like other sources
  - Can run periodic auto-sync loop when enabled
- Per-IOC lookup (UI + API): `POST /alerts/opencti/lookup` with JSON `{"value": "<ioc>", "first": 20}` — server calls `{OPENCTI_URL}/graphql` with `stixCyberObservables(search: …)` (same token as pull).
- When `OPENCTI_AUTO_SYNC_ENABLED=true`, set `THREAT_INTEL_PULL_SOURCE` to `opencti` (default), `abuseipdb`, or `both` to choose scheduled pull behavior.

### AbuseIPDB (IP reputation)

- Pull ingestion endpoint: `POST /alerts/connectors/pull/abuseipdb` (query params: `limit`, `confidence_minimum`) — fetches the AbuseIPDB blacklist and ingests each IP as an alert. Availability depends on your AbuseIPDB plan.
- Required env: `ABUSEIPDB_API_KEY` (from [AbuseIPDB API](https://www.abuseipdb.com/api)) — same env-or-secret-service pattern as other keys.
- Optional env: `ABUSEIPDB_API_BASE`, `ABUSEIPDB_BLACKLIST_LIMIT`, `ABUSEIPDB_CONFIDENCE_MINIMUM`.
- Per-IP lookup (UI + API): `POST /alerts/abuseipdb/lookup` with JSON `{"value": "<ipv4-or-ipv6>", "maxAgeInDays": 90}` — server calls AbuseIPDB `GET /check`.
- Case **Observables** tab includes a **Threat intel source** dropdown (OpenCTI vs AbuseIPDB) for the **Lookup** action; AbuseIPDB applies only to IP observables.

### Generic SIEM

- Webhook endpoint: `POST /alerts/alerts/webhook/generic`
- Behavior: Accepts JSON payload, normalizes with source/severity/title/description mapping.

## Alert -> Case Workflow

- Alert actions:
  - Assign: `POST /alerts/alerts/{alert_id}/assign`
  - Add tags: `POST /alerts/alerts/{alert_id}/tags`
  - Status lifecycle: `POST /alerts/alerts/{alert_id}/status` (`new|triaged|escalated|closed`)
  - Escalate: `POST /alerts/alerts/{alert_id}/escalate`
- Case actions:
  - Create from alert: `POST /cases/cases/from-alert`
  - Assignment tracking (`assigned_by`, `assigned_to`, `assigned_at`)
  - Ownership enforcement (owner/admin for status updates)
  - Case lifecycle (`open|in-progress|resolved|closed`)
  - Timeline, comments, tasks
  - Evidence files: `POST /cases/cases/{id}/evidence` (multipart `file` + optional `uploaded_by`), download `GET …/evidence/{evidence_id}/file`, delete `DELETE …/evidence/{evidence_id}` — files on disk (`CASE_EVIDENCE_DIR`), metadata on case JSON; UI tab **Evidence** on case detail.

## Security Controls

- OIDC/JWT validation via Keycloak in `api-gateway`
- RBAC checks for case/automation routes
- Zero-trust internal auth using `x-internal-token` (`INTERNAL_SERVICE_TOKEN`)
- SIEM ingress IP allowlist (`INGEST_ALLOWLIST`)
- Vault-ready deployment (`vault` service)
- Centralized encrypted secret storage (`secret-service`) for runtime API keys
- Field encryption at rest for sensitive case fields (`DATA_ENCRYPTION_KEY` / Fernet)
- Audit trail through Kafka event history (`alerts.*`, `cases.updated`)

## Admin Panel - API Keys

- Admin UI page: `/admin`
- Requirement: Keycloak **admin** bearer token
- Panel can set/update API keys and integration secrets at runtime (stored encrypted in PostgreSQL via `secret-service`)
- Gateway admin endpoints:
  - List: `GET /secrets/secrets`
  - Upsert: `PUT /secrets/secrets/{key}`
  - Delete: `DELETE /secrets/secrets/{key}`

Supported runtime keys include SIEM, OpenCTI, SMTP, and webhook credentials (e.g. `OPENCTI_TOKEN`, `SPLUNK_TOKEN`, `SENTINEL_CLIENT_SECRET`, `SLACK_WEBHOOK_URL`).

## Real-Time Operations (Phase 2)

- WebSocket event stream endpoint: `GET ws://<gateway>/stream/events`
- Frontend live stream widget on Alerts and Cases pages
- Observable worker consumes `observables.created` and stores IOCs (dedupe + Elasticsearch index)

## Phase 3 Additions

- Notification microservice:
  - Kafka consumer on `cases.updated`
  - SMTP, Slack webhook, and Discord webhook dispatch
  - Test endpoint: `POST /notifications/notifications/test` via gateway
- API Gateway routing now includes `notifications` service.

## FE/BE Integration Status

- Alerts page: assign, tag, status update, escalate to case
- Observables page consumes live backend data from `GET /observables/observables`
- OpenCTI: use `NEXT_PUBLIC_OPENCTI_URL` in the frontend for a nav link; server-side sync uses `OPENCTI_*` on alert-service

## Tests

- `tests/test_case_encryption.py` validates encryption/decryption of sensitive payload fields
- Run tests:

```bash
pytest -q tests
```

## ❤️ Support This Project
If you find this useful, consider sponsoring me on GitHub!

👉 https://github.com/sponsors/adriyansyah-mf