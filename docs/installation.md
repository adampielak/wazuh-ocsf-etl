# Installation

## Prerequisites

- Linux x86_64
- Rust 1.91.1+ (pinned via `rust-toolchain.toml` — build only, not needed at runtime)
- ClickHouse 22.x+ reachable over HTTP
- Wazuh manager 4.x with JSON output enabled

Enable JSON alerts in Wazuh if needed:

```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
</ossec_config>
```

Restart Wazuh:

```bash
systemctl restart wazuh-manager
```

## Build

```bash
cargo build --release
cargo test
```

Binary output:
- `target/release/wazuh-ocsf-etl`

## Recommended install (one command)

```bash
# Standard — creates dedicated 'wazuh-ocsf' system user
sudo ./install.sh ./target/release/wazuh-ocsf-etl

# If alerts.json is readable only by root (hardened / source builds)
sudo ./install.sh --run-as-root ./target/release/wazuh-ocsf-etl
```

Then:

```bash
nano /opt/wazuh-ocsf/.env
systemctl start wazuh-ocsf-etl
systemctl status wazuh-ocsf-etl
journalctl -u wazuh-ocsf-etl -f
```

## Manual install

```bash
install -m 755 target/release/wazuh-ocsf-etl /usr/local/bin/
useradd -r -s /sbin/nologin -d /opt/wazuh-ocsf wazuh-ocsf
mkdir -p /opt/wazuh-ocsf/{state,config}
cp .env /opt/wazuh-ocsf/.env
cp config/field_mappings.toml /opt/wazuh-ocsf/config/
chown -R wazuh-ocsf:wazuh-ocsf /opt/wazuh-ocsf
usermod -aG wazuh wazuh-ocsf
```

Create service and start:

```bash
systemctl daemon-reload
systemctl enable --now wazuh-ocsf-etl
```

## First run recommendation

- Default `SEEK_TO_END_ON_FIRST_RUN=true` avoids replaying very large existing alert files.
- Set to `false` only when you intentionally need full historical backfill.

## Next

- Configure settings: [configuration.md](configuration.md)
- ZeroMQ mode setup: [zeromq.md](zeromq.md)
- Ops and troubleshooting: [operations.md](operations.md)
- Production gotchas: [deployment-notes.md](deployment-notes.md)
