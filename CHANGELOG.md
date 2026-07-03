# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [2026-07-03] — Wazuh 4.14.6 Upgrade (ZeroMQ, gcc 15 patches)

### Changed

- **Wazuh upgraded from 4.14.5 to 4.14.6** on the production Wazuh manager host, built from source with `USE_ZEROMQ=yes`. Pipeline continues running in `INPUT_MODE=zeromq` without interruption.

### Fixed (build patches for gcc 15 / Ubuntu 25.04)

- **Missing `#include <cstdint>`** in six `versionMatcher` headers (`versionObjectCalVer.hpp`, `versionObjectDpkg.hpp`, `versionObjectMajorMinor.hpp`, `versionObjectPEP440.hpp`, `versionObjectRpm.hpp`, `versionObjectSemVer.hpp`): gcc 15 no longer imports `uint*_t` types transitively — explicit `#include <cstdint>` added to each file.

- **`czmq_prelude.h` type-size checks** (`/usr/include/czmq_prelude.h`): gcc 15 with Wazuh's include chain causes `UCHAR_MAX`/`USHRT_MAX`/`UINT_MAX` to be undefined when `czmq_prelude.h` is evaluated, triggering false `#error` directives. Fix: wrap each check with `#ifdef` guard (backup saved as `czmq_prelude.h.bak-wazuh-build`).

### Updated

- `scripts/wazuh-build-from-source.sh`: default `WAZUH_VERSION` bumped to `4.14.6`; added gcc 15 patch steps and Ubuntu 25.04 to tested platforms.
- `docs/wazuh-build-from-source.md`: version compatibility matrix updated; gcc 15 known issues and patches documented.

---

### Fixed

- **ZMQ multipart frames** (`src/input/zmq.rs`): Wazuh sends alerts as a 2-frame ZMQ multipart message `[topic="ossec.alerts", JSON]`. The previous code joined all frames into a single string, producing `ossec.alertsJSON...` which failed JSON parsing silently (logged at `debug` level only). No events were reaching ClickHouse. Fix: take the last frame as the JSON payload.

- **ZMQ CLOSE-WAIT hang** (`src/input/zmq.rs`): When `wazuh-analysisd` restarts, the SUB socket enters `CLOSE-WAIT` state. `recv()` never returns an error — the process hangs indefinitely and stops inserting data. Fix: added a 30-second `tokio::time::timeout` on `recv()`; on elapsed the socket is closed and reconnection is attempted.

- **ClickHouse 26.x schema validation failure** (`src/main.rs`): `clickhouse-rs 0.14.2` uses `RowBinaryWithNamesAndTypes` format to fetch and validate table schema before inserts. ClickHouse 26.x changed the response format for this, causing a spurious `schema mismatch: database schema has no column named time` error on every flush despite the schema being correct. Fix: `.with_validation(false)` switches to plain `RowBinary`, which is safe because the `OcsfRecord` struct fields match the table columns exactly.

---

## Earlier history

See `git log` for full commit history prior to this changelog.
