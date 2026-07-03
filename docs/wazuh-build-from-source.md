# Wazuh — Build from Source (ZeroMQ)

## Why build from source

Official Wazuh binary packages (`.deb`, `.rpm`) distributed via
`packages.wazuh.com` do **not** include ZeroMQ output support.

If you run `INPUT_MODE=zeromq` in wazuh-ocsf-etl, Wazuh **must** be built
from source with `USE_ZEROMQ=yes`.  Installing or upgrading via `apt` silently
drops ZeroMQ and breaks the ETL pipeline.

## Supported version

The script targets **Wazuh 4.14.6** — the latest stable release tested with
this ETL pipeline.  It will be updated with each new Wazuh release that is
verified compatible with the current pipeline version.

Check `scripts/wazuh-build-from-source.sh` for the default `WAZUH_VERSION`
value; override it on the command line if needed.

## Quick start

```bash
# Fresh install or upgrade to default version (4.14.6)
sudo bash scripts/wazuh-build-from-source.sh

# Override version
sudo bash scripts/wazuh-build-from-source.sh 4.14.5
```

Requires: Debian/Ubuntu, root, internet access.  Tested on Ubuntu 22.04, 24.04, and 25.04.

Build takes **15–40 minutes** depending on CPU cores.

## What the script does

| Step | Action |
|------|--------|
| 1 | Install build dependencies (gcc, cmake, libzmq3-dev, libczmq-dev, etc.) |
| 2 | Backup `/var/ossec/etc/ossec.conf` |
| 3 | Download source tarball from GitHub (`v<VERSION>.tar.gz`) |
| 4 | `make deps TARGET=server` |
| 4a | **[gcc ≥ 15 only]** Patch six `versionMatcher` headers — add `#include <cstdint>` |
| 4b | **[gcc ≥ 15 only]** Patch `/usr/include/czmq_prelude.h` — add `#ifdef` guards around type-size checks |
| 4c | `make TARGET=server USE_ZEROMQ=yes` |
| 5 | Write `preloaded-vars.conf` for unattended `install.sh` |
| 6 | Remove `apt-mark hold` on `wazuh-manager`, stop `wazuh-manager` |
| 7 | Run `install.sh` in update mode |
| 8 | Restore `ossec.conf` from backup |
| 9 | Verify version and ZeroMQ in installed binary |
| 10 | Start `wazuh-manager`, re-apply `apt-mark hold`, print status |

Log is written to `/var/log/wazuh-build-<VERSION>.log`.

Steps 4a and 4b are **applied automatically** when gcc ≥ 15 is detected — no manual action needed.

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

## Known build issues

### wazuh-maild linker error (4.14.5+)

`wazuh-maild` may fail to link with:

```
undefined reference to `wdbc_close'
```

This affects only the mail daemon (not used in typical SOC setups).
`wazuh-analysisd`, `wazuh-remoted`, `wazuh-db` and all other critical daemons
build and run correctly.  The script treats this as non-fatal — verify
post-install with `wazuh-control status`.

### gcc 15 / Ubuntu 25.04 — two required patches

When building on Ubuntu 25.04 (gcc 15.x), two source patches are required:

**1. Missing `#include <cstdint>` in versionMatcher headers**

gcc 15 no longer imports `uint8_t`/`uint16_t`/`uint32_t` transitively.
Six headers in `src/wazuh_modules/vulnerability_scanner/src/scanOrchestrator/versionMatcher/` fail with `'uint16_t' does not name a type`.

Fix (apply before `make TARGET=server USE_ZEROMQ=yes`):

```bash
for f in versionObjectCalVer.hpp versionObjectDpkg.hpp versionObjectMajorMinor.hpp \
          versionObjectPEP440.hpp versionObjectRpm.hpp versionObjectSemVer.hpp; do
  sed -i 's/#include <iostream>/#include <cstdint>\n#include <iostream>/' \
    /opt/wazuh-src/wazuh-4.14.6/src/wazuh_modules/vulnerability_scanner/src/scanOrchestrator/versionMatcher/"$f"
done
```

**2. `czmq_prelude.h` type-size check failure**

When Wazuh headers are included before `<czmq.h>`, `UCHAR_MAX`/`USHRT_MAX`/`UINT_MAX` are undefined at the point `czmq_prelude.h` evaluates its `#if` guards.  This triggers false compile errors:

```
#error "Cannot compile: must change definition of 'byte'."
#error "Cannot compile: must change definition of 'dbyte'."
#error "Cannot compile: must change definition of 'qbyte'."
```

Fix (patch the system header — backup is created):

```bash
cp /usr/include/czmq_prelude.h /usr/include/czmq_prelude.h.bak-wazuh-build
python3 - <<'EOF'
with open('/usr/include/czmq_prelude.h', 'r') as f:
    c = f.read()
old = '#if (UCHAR_MAX != 0xFF)\n#   error "Cannot compile: must change definition of \'byte\'."\n#endif\n#if (USHRT_MAX != 0xFFFFU)\n#    error "Cannot compile: must change definition of \'dbyte\'."\n#endif\n#if (UINT_MAX != 0xFFFFFFFFU)\n#    error "Cannot compile: must change definition of \'qbyte\'."\n#endif'
new = '#ifdef UCHAR_MAX\n#if (UCHAR_MAX != 0xFF)\n#   error "Cannot compile: must change definition of \'byte\'."\n#endif\n#endif\n#ifdef USHRT_MAX\n#if (USHRT_MAX != 0xFFFFU)\n#    error "Cannot compile: must change definition of \'dbyte\'."\n#endif\n#endif\n#ifdef UINT_MAX\n#if (UINT_MAX != 0xFFFFFFFFU)\n#    error "Cannot compile: must change definition of \'qbyte\'."\n#endif\n#endif'
with open('/usr/include/czmq_prelude.h', 'w') as f:
    f.write(c.replace(old, new))
print('done')
EOF
```

Both patches are idempotent and safe to re-apply.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Download 404 | Check tag exists: `https://github.com/wazuh/wazuh/tags` |
| `libzmq3-dev` not found | `apt-get update` first, or use `libzmq5-dev` on older distros |
| `'uint16_t' does not name a type` | gcc ≥ 15: patches 4a/4b were not applied — script applies them automatically if gcc ≥ 15 is detected |
| `#error "Cannot compile: must change definition of 'byte'."` | gcc ≥ 15: `czmq_prelude.h` patch (4b) was not applied — re-run the script |
| ZeroMQ not in binary after install | `apt install` overwrote the build — re-run this script |
| `ossec.conf` overwritten | Restore from `/var/ossec/etc/ossec.conf.bak-pre-*` |
| ETL not receiving events | Check ZeroMQ in ossec.log; confirm `ZEROMQ_URI` matches `ossec.conf` |
| ETL shows no events after Wazuh restart | Port race: ETL held port 11111 while manager restarted. Restart ETL after manager is fully up: `systemctl restart wazuh-ocsf-etl` |

## Version compatibility matrix

| Wazuh version | ETL tested | ZeroMQ build | Notes |
|---------------|-----------|--------------|-------|
| 4.14.6 | ✓ | ✓ | Current default; gcc 15 patches required on Ubuntu 25.04 |
| 4.14.5 | ✓ | ✓ | Previous production version; wazuh-maild linker issue (non-critical) |
| 4.14.4-rc2 | ✓ | ✓ | Older tested version |

This table is updated with each verified Wazuh release.
