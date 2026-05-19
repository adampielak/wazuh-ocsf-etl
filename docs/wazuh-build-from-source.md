# Wazuh — Build from Source (ZeroMQ)

## Why build from source

Official Wazuh binary packages (`.deb`, `.rpm`) distributed via
`packages.wazuh.com` do **not** include ZeroMQ output support.

If you run `INPUT_MODE=zeromq` in wazuh-ocsf-etl, Wazuh **must** be built
from source with `USE_ZEROMQ=yes`.  Installing or upgrading via `apt` silently
drops ZeroMQ and breaks the ETL pipeline.

## Supported version

The script targets **Wazuh 4.14.5** — the latest stable release tested with
this ETL pipeline.  It will be updated with each new Wazuh release that is
verified compatible with the current pipeline version.

Check `scripts/wazuh-build-from-source.sh` for the default `WAZUH_VERSION`
value; override it on the command line if needed.

## Quick start

```bash
# Fresh install or upgrade to default version (4.14.5)
sudo bash scripts/wazuh-build-from-source.sh

# Override version
sudo bash scripts/wazuh-build-from-source.sh 4.14.6
```

Requires: Debian/Ubuntu, root, internet access.  Tested on Ubuntu 22.04 and 24.04.

Build takes **15–40 minutes** depending on CPU cores.

## What the script does

| Step | Action |
|------|--------|
| 1 | Install build dependencies (gcc, cmake, libzmq3-dev, libczmq-dev, etc.) |
| 2 | Backup `/var/ossec/etc/ossec.conf` |
| 3 | Download source tarball from GitHub (`v<VERSION>.tar.gz`) |
| 4 | `make deps TARGET=server` then `make TARGET=server USE_ZEROMQ=yes` |
| 5 | Write `preloaded-vars.conf` for unattended `install.sh` |
| 6 | Stop `wazuh-manager` |
| 7 | Run `install.sh` in update mode |
| 8 | Restore `ossec.conf` from backup |
| 9 | Verify version and ZeroMQ in installed binary |
| 10 | Start `wazuh-manager` and print status |

Log is written to `/var/log/wazuh-build-<VERSION>.log`.

## Enable ZeroMQ in ossec.conf

After build, add to `/var/ossec/etc/ossec.conf` inside `<ossec_config>`:

```xml
<global>
  <zeromq_output>yes</zeromq_output>
  <!-- bind to localhost when ETL runs on the same host -->
  <zeromq_uri>tcp://127.0.0.1:11111</zeromq_uri>
  <!-- use 0.0.0.0 to allow remote ETL instances -->
  <!-- <zeromq_uri>tcp://0.0.0.0:11111</zeromq_uri> -->
</global>
```

Restart after editing:

```bash
systemctl restart wazuh-manager
grep -i zeromq /var/ossec/logs/ossec.log | tail -5
# expected: "ZeroMQ output enabled"
```

## Verify ZeroMQ is compiled in

```bash
strings /var/ossec/bin/wazuh-analysisd | grep zeromq_output
# must return: zeromq_output
# empty output = ZeroMQ not compiled — ETL zeromq mode will not work
```

## After upgrading Wazuh

1. Restart the ETL pipeline (it reconnects automatically on startup):

```bash
systemctl restart wazuh-ocsf-etl
journalctl -u wazuh-ocsf-etl -f
```

2. Verify events are flowing into ClickHouse:

```bash
curl -s 'http://localhost:8123/?query=SELECT+count(),max(time)+FROM+wazuh_ocsf.ocsf_<agent>+WHERE+time>now()-300'
```

## Upgrading Wazuh via apt — DO NOT

Running `apt upgrade wazuh-manager` or `apt install wazuh-manager` replaces
the source-built binary with a package binary that lacks ZeroMQ.  The ETL
will connect but receive no events.

**Always use this script to upgrade when `INPUT_MODE=zeromq` is active.**

Hold the package to prevent accidental upgrades:

```bash
apt-mark hold wazuh-manager
```

To unhold before a deliberate upgrade via this script:

```bash
apt-mark unhold wazuh-manager
# run the script, then re-hold
apt-mark hold wazuh-manager
```

## Known build issue: wazuh-maild linker error

On Wazuh 4.14.5, `wazuh-maild` may fail to link with:

```
undefined reference to `wdbc_close'
```

This affects only the mail daemon (not used in typical SOC setups).
`wazuh-analysisd`, `wazuh-remoted`, `wazuh-db` and all other critical daemons
build and run correctly.  The script treats this as non-fatal — verify
post-install with `wazuh-control status`.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Download 404 | Check tag exists: `https://github.com/wazuh/wazuh/tags` |
| `libzmq3-dev` not found | `apt-get update` first, or use `libzmq5-dev` on older distros |
| ZeroMQ not in binary after install | `apt install` overwrote the build — re-run this script |
| `ossec.conf` overwritten | Restore from `/var/ossec/etc/ossec.conf.bak-pre-*` |
| ETL not receiving events | Check ZeroMQ in ossec.log; confirm `ZEROMQ_URI` matches `ossec.conf` |

## Version compatibility matrix

| Wazuh version | ETL tested | ZeroMQ build | Notes |
|---------------|-----------|--------------|-------|
| 4.14.5 | ✓ | ✓ | Current default; wazuh-maild linker issue (non-critical) |
| 4.14.4-rc2 | ✓ | ✓ | Previous production version |

This table is updated with each verified Wazuh release.
