# ZeroMQ Mode

## When to use

Use ZeroMQ mode if you need very low latency or remote subscription from another machine.

```dotenv
INPUT_MODE=zeromq
ZEROMQ_URI=tcp://localhost:11111
```

## Critical prerequisite

Default Wazuh binary packages do not include ZeroMQ output support.

Use the provided build script — it handles dependencies, source patches, build, install, and `ossec.conf` backup/restore automatically:

```bash
sudo bash scripts/wazuh-build-from-source.sh          # latest tested version
sudo bash scripts/wazuh-build-from-source.sh 4.14.6   # explicit version
```

Or build manually:

```bash
apt-get install -y libzmq3-dev libczmq-dev
make deps TARGET=server
make TARGET=server USE_ZEROMQ=yes
```

> **Ubuntu 25.04 / gcc 15:** two source patches are required before `make TARGET=server USE_ZEROMQ=yes`. The build script applies them automatically. For manual builds see [docs/wazuh-build-from-source.md](wazuh-build-from-source.md#known-build-issues).

## Minimal enablement steps

1. Build Wazuh from source using `scripts/wazuh-build-from-source.sh`
2. Enable in `/var/ossec/etc/ossec.conf`:

```xml
<global>
  <zeromq_output>yes</zeromq_output>
  <zeromq_uri>tcp://0.0.0.0:11111/</zeromq_uri>
</global>
```

4. Restart Wazuh manager
5. Verify logs show ZeroMQ output enabled

## Trade-offs

- File mode:
  strongest reliability and replay ability
- ZeroMQ mode:
  lowest latency, but PUB/SUB is at-most-once

If zero data loss is mandatory, prefer file mode.
