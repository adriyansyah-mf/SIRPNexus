# Wazuh Integration Script

This folder contains a ready-to-use Wazuh custom integration script that forwards alerts to SIRP.

## Files

- `sirp_integration.py`: sends Wazuh alert JSON to `POST /ingest/wazuh` on the API Gateway.

## Environment Variables

- `SIRP_INGEST_URL` (default: `http://localhost:8000/ingest/wazuh`)
- `SIRP_WEBHOOK_TOKEN` (optional; must match `INBOUND_WEBHOOK_TOKEN` in SIRP `.env`)
- `SIRP_TIMEOUT_SECONDS` (default: `10`)
- `SIRP_RETRIES` (default: `3`)
- `SIRP_RETRY_BACKOFF_SECONDS` (default: `1.5`)

## Manual Test

```bash
python3 integrations/wazuh/sirp_integration.py <<'EOF'
{"data":{"rule":{"level":12,"description":"Wazuh test alert"},"agent":{"name":"wazuh-agent-01"}}}
EOF
```

## Wazuh `ossec.conf` (Integrator / custom-*)

Wazuh runs an executable named exactly like `<name>` under `/var/ossec/integrations/`
(e.g. `<name>custom-w2thive</name>` → file `/var/ossec/integrations/custom-w2thive`).

Copy or symlink this repo’s `sirp_integration.py` to that path, then:

```bash
chmod 750 /var/ossec/integrations/custom-w2thive
chown root:ossec /var/ossec/integrations/custom-w2thive
```

The script receives **argv[1]** = alert JSON file, **argv[2]** = `<api_key>`, **argv[3]** = `<hook_url>` (see [Wazuh integration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)).

Example (same shape as TheHive-style custom blocks):

```xml
<integration>
  <name>custom-w2thive</name>
  <hook_url>http://103.204.15.99:9000/ingest/wazuh</hook_url>
  <api_key>YOUR_SHARED_SECRET</api_key>
  <alert_format>json</alert_format>
  <level>10</level>
</integration>
```

- **`hook_url`**: Use the full SIRP API Gateway URL. If you only set the base (e.g. `http://103.204.15.99:9000` with no path), the script **appends** `/ingest/wazuh` automatically.
- **`api_key`**: Must match **`INBOUND_WEBHOOK_TOKEN`** in SIRP `.env`. The script sends it as header `x-webhook-token`. If `INBOUND_WEBHOOK_TOKEN` is empty, the gateway does not require the header (still restrict **`INGEST_ALLOWLIST`** on the alert-service to the Wazuh manager IP).

After editing `ossec.conf`, restart the Wazuh manager.
