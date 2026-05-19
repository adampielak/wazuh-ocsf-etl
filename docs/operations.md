# Operations

## Service management

```bash
systemctl status wazuh-ocsf-etl
systemctl restart wazuh-ocsf-etl
journalctl -u wazuh-ocsf-etl -f
```

## Health checks

- Pipeline logs show regular flushes/rows
- ClickHouse ping endpoint responds `Ok.`
- State file offset moves as new alerts arrive

## Troubleshooting quick checks

### No data in ClickHouse

- Validate Wazuh is writing alerts
- Validate `.env` ClickHouse credentials/URL
- Check service user can read alerts file
- Confirm tables exist in target database

### Permission denied on alerts.json

Add service user to `wazuh` group, then restart service.

### Behind on backlog

Increase batching and verify ClickHouse performance:
- `BATCH_SIZE`
- `CHANNEL_CAP`
- `FLUSH_INTERVAL_SECS`

## Log rotation behavior

Handled automatically using inode and file-size checks.

- Rotation while running: reopens new file from 0
- Rotation while stopped: inode mismatch on startup triggers safe reset

## Upgrade

Recommended:

```bash
cargo build --release
sudo ./install.sh ./target/release/wazuh-ocsf-etl
systemctl start wazuh-ocsf-etl
```

Configuration and field mappings are preserved.

## ZeroMQ mode — Wazuh upgrade note

Wazuh binary packages (.deb) do **not** include ZeroMQ support.
If `INPUT_MODE=zeromq` is in use, Wazuh must be built from source with:

```bash
cd /root/wazuh-<VERSION>/src
make deps TARGET=server
make TARGET=server USE_ZEROMQ=yes
```

Before running `install.sh`, create `etc/preloaded-vars.conf`:

```
USER_LANGUAGE="en"
USER_NO_STOP="y"
USER_INSTALL_TYPE="server"
USER_DIR="/var/ossec"
USER_UPDATE="y"
USER_ENABLE_UPDATE_CHECK="n"
```

Then restore `ossec.conf` from backup after install — `install.sh` may overwrite it.
