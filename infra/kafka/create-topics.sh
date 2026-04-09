#!/usr/bin/env bash
set -euo pipefail
TOPICS=(alerts.ingested alerts.normalized observables.created analyzers.jobs analyzers.results cases.updated alerts.normalized.dlq analyzers.jobs.dlq)
KAFKA_CONTAINER=${KAFKA_CONTAINER:-kafka}
for t in "${TOPICS[@]}"; do
  docker exec "$KAFKA_CONTAINER" kafka-topics --bootstrap-server kafka:9092 --create --if-not-exists --topic "$t" --partitions 3 --replication-factor 1 || true
done
