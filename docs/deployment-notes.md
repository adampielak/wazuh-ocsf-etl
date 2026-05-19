# Deployment Notes

Practical gotchas and decisions from real production deployments.

## `--run-as-root` vs dedicated user

`install.sh` creates a `wazuh-ocsf` system user by default.  On hardened Wazuh
builds — particularly those compiled from source — `alerts.json` may be
readable only by root, making the dedicated-user approach fail silently
(service starts but reads nothing).

Use `--run-as-root` when:

- Wazuh was compiled from source with custom umask/ownership
- Adding `wazuh-ocsf` to the `wazuh` group still yields `Permission denied`
- You are running `INPUT_MODE=zeromq` (no file access needed, but root simplifies startup)

```bash
sudo ./install.sh --run-as-root ./target/release/wazuh-ocsf-etl
```

Verify the actual service user after install:

```bash
grep '^User=' /etc/systemd/system/wazuh-ocsf-etl.service
```

## alerts.json permission denied

If you see `Permission denied` on `/var/ossec/logs/alerts/alerts.json`:

```bash
# Option 1 — add service user to wazuh group (preferred)
usermod -aG wazuh wazuh-ocsf
systemctl restart wazuh-ocsf-etl

# Option 2 — reinstall with --run-as-root
sudo ./install.sh --run-as-root ./target/release/wazuh-ocsf-etl
```

## State file location

Default state path is relative to `WorkingDirectory` (`/opt/wazuh-ocsf`):

```
STATE_FILE=state/alerts.pos
# resolves to: /opt/wazuh-ocsf/state/alerts.pos
```

For multi-node (cluster) deployments use a unique path per node:

```
STATE_FILE=state/<hostname>/alerts.pos
```

The directory is created automatically on first run.

## Re-running install.sh (upgrades)

`install.sh` is safe to re-run on existing installations — it updates the
binary and service unit without overwriting `.env` or `field_mappings.toml`.

```bash
cargo build --release
sudo ./install.sh ./target/release/wazuh-ocsf-etl   # or --run-as-root
systemctl restart wazuh-ocsf-etl
```

## ZeroMQ: bind address in ossec.conf

When collocated, bind ZeroMQ to `127.0.0.1` rather than `0.0.0.0` unless
remote ETL instances need to subscribe:

```xml
<global>
  <zeromq_output>yes</zeromq_output>
  <zeromq_uri>tcp://127.0.0.1:11111</zeromq_uri>
</global>
```

ETL `.env` must match:

```dotenv
ZEROMQ_URI=tcp://localhost:11111
```

Verify ZeroMQ is compiled into the running binary:

```bash
strings /var/ossec/bin/wazuh-analysisd | grep zeromq_output
```

Expected output: `zeromq_output` (empty = not compiled, use file mode instead).

Verify it is enabled in runtime logs:

```bash
grep -i zeromq /var/ossec/logs/ossec.log | tail -5
```

## ZeroMQ mode: no state file needed

In `INPUT_MODE=zeromq` there is no file position to track — events come from
a live socket.  The `STATE_FILE` value is ignored and no state file is created.
Log rotation handling is also not applicable.

## ClickHouse: tables are auto-created

On first flush the pipeline creates the target database and per-agent tables
automatically.  No manual DDL needed.  If you change the schema (e.g. update
the binary to a newer version that adds columns), new columns are added
automatically via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.

Verify tables after first data arrives:

```bash
curl -s 'http://localhost:8123/?query=SHOW+TABLES+FROM+wazuh_ocsf'
```

## ClickHouse: listen address

Default ClickHouse config listens on all interfaces.  For single-host setups
restrict to localhost:

```xml
<!-- /etc/clickhouse-server/config.d/listen.xml -->
<clickhouse>
    <listen_host>127.0.0.1</listen_host>
</clickhouse>
```

Restart ClickHouse after changing this.

## ClickHouse: memory cap on shared servers

On servers shared with Wazuh manager and other services, cap ClickHouse memory
to prevent OOM.  Wazuh manager idles at 3+ GB RSS:

```xml
<!-- /etc/clickhouse-server/config.d/memory_limit.xml -->
<clickhouse>
    <max_server_memory_usage>5368709120</max_server_memory_usage>
    <merges_mutations_memory_usage_to_ram_ratio>0.3</merges_mutations_memory_usage_to_ram_ratio>
</clickhouse>
```

## Grafana: alert rules provisioned via API

If you import dashboards (or alert rules) via the Grafana API, the resulting
rules carry `provenance=api`.  Grafana 10+ prevents modifying them via the UI
or API header `X-Disable-Provenance`.  To pause or delete such rules:

```bash
# Identify rule UIDs
curl -s http://localhost:3000/api/v1/provisioning/alert-rules \
     -u admin:<password> | python3 -m json.tool | grep '"uid"'

# Pause via direct SQLite update (Grafana must be running)
sqlite3 /var/lib/grafana/grafana.db \
  "UPDATE alert_rule SET is_paused=1 WHERE uid IN ('uid1','uid2');"
```

Restart Grafana after:

```bash
systemctl restart grafana-server
```

## Grafana: dashboard import

Use the bundled `grafana-dashboard.json` and `grafana-etl-pipeline.json`.
Upload via API to preserve UIDs and avoid duplicate dashboards:

```bash
# Wrap in the required envelope and POST
python3 -c "
import json, sys
d = json.load(open('grafana-dashboard.json'))
print(json.dumps({'dashboard': d, 'overwrite': True, 'folderId': 0}))
" | curl -s -X POST http://localhost:3000/api/dashboards/db \
     -H 'Content-Type: application/json' \
     -u admin:<password> \
     -d @-
```

## Wazuh upgrade: ZeroMQ builds from source

Official Wazuh `.deb`/`.rpm` packages do **not** include ZeroMQ.  If you
upgrade Wazuh via `apt upgrade`, ZeroMQ support is silently dropped and the
ETL pipeline loses its input.

Always rebuild from source when `INPUT_MODE=zeromq` is in use.  See
[operations.md](operations.md) for the full procedure including
`preloaded-vars.conf` for unattended install.

After any Wazuh upgrade, verify ZeroMQ is still compiled in:

```bash
strings /var/ossec/bin/wazuh-analysisd | grep zeromq_output
```

## Wazuh upgrade: restore ossec.conf

`install.sh` may overwrite `/var/ossec/etc/ossec.conf`.  Back up before
upgrading and restore after:

```bash
cp /var/ossec/etc/ossec.conf /root/ossec.conf.bak
# ... run install.sh ...
cp /root/ossec.conf.bak /var/ossec/etc/ossec.conf
systemctl restart wazuh-manager
```

## First-run: large existing alerts file

If `alerts.json` already contains months of data, `SEEK_TO_END_ON_FIRST_RUN=true`
(default) avoids replaying it all on first start.  Only set `false` when you
explicitly want to backfill ClickHouse with historical data.

## Verify the pipeline is ingesting

```bash
# ClickHouse ping
curl -s http://localhost:8123/ping

# Events in the last hour (replace table name with your agent)
curl -s 'http://localhost:8123/?query=SELECT+count(),max(time)+FROM+wazuh_ocsf.ocsf_<agent>+WHERE+time>now()-3600'

# Service health
systemctl status wazuh-ocsf-etl
journalctl -u wazuh-ocsf-etl -f
```
