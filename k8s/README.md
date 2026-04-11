# Kubernetes deployment

SIRP **bisa** dijalankan di Kubernetes: setiap layanan punya `Dockerfile` dan nama host internal yang sama pola dengan Docker Compose (`http://alert-service:8001`, `http://case-service:8001`, dll.).

Repo ini **tidak** memuat chart lengkap untuk seluruh stack (Kafka, Zookeeper, Postgres, Elasticsearch, Keycloak, dll.). Di cluster produksi biasanya memakai:

- **Managed**: RDS/Cloud SQL, ElastiCache/Memorystore, MSK/Confluent, OpenSearch/Elastic Cloud  
- **Helm**: Bitnami / Strimzi (Kafka), Helm Postgres/Redis, dsb.

## Yang perlu Anda siapkan

1. **Image** — build & push ke registry Anda, mis. `ghcr.io/org/sirp-alert-service:tag` (sama untuk `api-gateway`, `case-service`, `frontend`, …).
2. **Secret / ConfigMap** — salin variabel dari `.env.example` / `.env` (minimal `APP_AUTH_JWT_SECRET`, `INTERNAL_SERVICE_TOKEN`, `DATA_ENCRYPTION_KEY`, DSN Postgres, `KAFKA_BOOTSTRAP_SERVERS`, `REDIS_URL`, `ELASTICSEARCH_URL`, kredensial SIEM).
3. **Service DNS** — Deployment SIRP harus bisa resolve nama seperti di Compose:
   - `postgres`, `redis`, `kafka`, `elasticsearch`, `secret-service`, `alert-service`, `case-service`, `observable-service`, `automation-service`, `notification-service`, `api-gateway`
   - Atau override URL lewat env (`ALERT_SERVICE_URL`, `CASE_SERVICE_URL`, …) ke Service K8s yang Anda buat.
4. **case-service** — set `API_GATEWAY_URL` ke URL internal gateway (mis. `http://api-gateway:8000`).
5. **Ingress** — ekspos `frontend` (Next) dan/atau `api-gateway` (REST + WebSocket); WebSocket butuh annotation yang sesuai (nginx/contour).

## Contoh minimal (`base.yaml`)

File `base.yaml` hanya **contoh** Deployment + Service untuk `alert-service` (2 replika). Gunakan sebagai pola; salin untuk layanan lain dengan `image`, `env`, `resources`, dan `livenessProbe` (`GET /health`) yang sesuai.

## Pendekatan cepat dari Compose

Alat seperti **Kompose** (`kompose convert`) bisa mengonversi `docker-compose.yml` menjadi manifest kasar; hasilnya perlu **direview** (StatefulSet untuk DB, Secret untuk env, tidak semua sidecar cocok).

## Produksi — checklist singkat

- Resource requests/limits per container  
- `PodDisruptionBudget` untuk gateway & stateless workers  
- NetworkPolicy jika cluster zero-trust  
- Backup Postgres + retention evidence (`CASE_EVIDENCE_DIR` → PVC)  
- Satu `INTERNAL_SERVICE_TOKEN` yang sama di semua service yang memverifikasi internal call  

Untuk Helm chart resmi satu tombol “install all”, itu bisa ditambahkan terpisah (community/ops) di atas manifest di folder ini.
