# Configuration

## Environment file

Primary runtime config is loaded from `.env`.

Common path in production:
- `/opt/wazuh-ocsf/.env`

## Essential variables

```dotenv
CLICKHOUSE_URL=http://localhost:8123
CLICKHOUSE_DATABASE=wazuh_ocsf
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=

INPUT_MODE=file
ALERTS_FILE=/var/ossec/logs/alerts/alerts.json
STATE_FILE=state/alerts.pos
SEEK_TO_END_ON_FIRST_RUN=true

BATCH_SIZE=5000
FLUSH_INTERVAL_SECS=5
CHANNEL_CAP=50000
```

## Input mode

- `INPUT_MODE=file` (default): reads local alerts file with full state + rotation handling
- `INPUT_MODE=zeromq`: subscribes to Wazuh ZeroMQ stream (advanced)

For ZeroMQ details and prerequisites, see [zeromq.md](zeromq.md).

## First-run behavior

When state file does not exist:

- `SEEK_TO_END_ON_FIRST_RUN=true`:
  starts at end, ingests only new alerts (safe default)
- `SEEK_TO_END_ON_FIRST_RUN=false`:
  replays full existing alerts file from byte 0

## Optional variables

- `SPECIAL_LOCATIONS` for shared table routing (agentless/integration sources)
- `DATA_TTL_DAYS` for retention TTL (disabled by default)
- `STORE_RAW_DATA` to keep/drop full raw JSON payload (true = full JSON stored; costs 40–70% extra storage)
- `OCSF_VALIDATE` to enable/disable schema validation warnings
- `UNMAPPED_FIELDS_FILE` path for unmapped-field report
- `RUST_LOG` log verbosity (`info`, `debug`, `trace`)

## Production .env — ZeroMQ mode

When collocated with Wazuh manager (requires ZeroMQ build, see [operations.md](operations.md)):

```dotenv
INPUT_MODE=zeromq
ZEROMQ_URI=tcp://localhost:11111

STATE_FILE=state/<hostname>/alerts.pos
UNMAPPED_FIELDS_FILE=/opt/wazuh-ocsf/state/unmapped_fields.json
FIELD_MAPPINGS_FILE=/opt/wazuh-ocsf/config/field_mappings.toml

SEEK_TO_END_ON_FIRST_RUN=true

BATCH_SIZE=5000
FLUSH_INTERVAL_SECS=5
CHANNEL_CAP=50000

OCSF_VALIDATE=true
RUST_LOG=info
STORE_RAW_DATA=true

# Shared tables for agentless/integration sources
SPECIAL_LOCATIONS=azure_ad,office365,syslog,kubernetes,k8s
```

## Field mappings

Custom mappings file:
- `config/field_mappings.toml`

Example:

```toml
[field_mappings]
"myapp.client_ip" = "src_ip"
"myapp.user"      = "actor_user"
"myapp.url"       = "url"
```

Changes are hot-reloaded (no service restart).

## Reference

For complete typed columns and source mapping details:
- [../FIELD_MAPPINGS.md](../FIELD_MAPPINGS.md)
