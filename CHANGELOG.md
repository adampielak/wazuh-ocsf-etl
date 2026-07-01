# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- **ZMQ multipart frames** (`src/input/zmq.rs`): Wazuh sends alerts as a 2-frame ZMQ multipart message `[topic="ossec.alerts", JSON]`. The previous code joined all frames into a single string, producing `ossec.alertsJSON...` which failed JSON parsing silently (logged at `debug` level only). No events were reaching ClickHouse. Fix: take the last frame as the JSON payload.

- **ZMQ CLOSE-WAIT hang** (`src/input/zmq.rs`): When `wazuh-analysisd` restarts, the SUB socket enters `CLOSE-WAIT` state. `recv()` never returns an error — the process hangs indefinitely and stops inserting data. Fix: added a 30-second `tokio::time::timeout` on `recv()`; on elapsed the socket is closed and reconnection is attempted.

- **ClickHouse 26.x schema validation failure** (`src/main.rs`): `clickhouse-rs 0.14.2` uses `RowBinaryWithNamesAndTypes` format to fetch and validate table schema before inserts. ClickHouse 26.x changed the response format for this, causing a spurious `schema mismatch: database schema has no column named time` error on every flush despite the schema being correct. Fix: `.with_validation(false)` switches to plain `RowBinary`, which is safe because the `OcsfRecord` struct fields match the table columns exactly.

---

## Earlier history

See `git log` for full commit history prior to this changelog.
