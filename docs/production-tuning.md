# Production Tuning

Server profile: **16-core Xeon E5-2690 v3, 16 GB RAM, Ubuntu 24.04**.
Shared with: Wazuh manager, Grafana, OpenSearch agent.

## ClickHouse server tuning

Custom overrides live in `/etc/clickhouse-server/config.d/`.

### Memory cap (`memory_limit.xml`)

```xml
<clickhouse>
    <!-- Hard cap: 5 GiB — prevents OOM on 16 GB system shared with Wazuh + Docker -->
    <max_server_memory_usage>5368709120</max_server_memory_usage>
    <!-- Background merge/mutation memory: 30% of max_server_memory_usage -->
    <merges_mutations_memory_usage_to_ram_ratio>0.3</merges_mutations_memory_usage_to_ram_ratio>
</clickhouse>
```

Rationale: Wazuh manager itself uses 3+ GB. Leaving 5 GB for ClickHouse avoids OOM
with zero swap configured on this host.

### Listen address (`listen.xml`)

```xml
<clickhouse>
    <listen_host>127.0.0.1</listen_host>
</clickhouse>
```

ClickHouse is not exposed externally — ETL and Grafana connect via localhost.

### System log TTL (`system_logs_ttl.xml`)

```xml
<clickhouse>
    <trace_log>     <ttl>event_date + INTERVAL 7 DAY</ttl>  </trace_log>
    <text_log>
        <ttl>event_date + INTERVAL 7 DAY</ttl>
        <level>warning</level>
    </text_log>
    <metric_log>    <ttl>event_date + INTERVAL 14 DAY</ttl> </metric_log>
    <part_log>      <ttl>event_date + INTERVAL 7 DAY</ttl>  </part_log>
    <query_log>     <ttl>event_date + INTERVAL 7 DAY</ttl>  </query_log>
    <asynchronous_metric_log>
        <ttl>event_date + INTERVAL 7 DAY</ttl>
    </asynchronous_metric_log>
</clickhouse>
```

Keeps system log tables small on 17 GB root volume.

## ETL pipeline tuning (`.env`)

Values tuned for ~500–2k EPS ZeroMQ mode on this server:

| Variable              | Value   | Notes                                     |
|-----------------------|---------|-------------------------------------------|
| `BATCH_SIZE`          | 5000    | Balanced for 500–2k EPS                   |
| `FLUSH_INTERVAL_SECS` | 5       | Timer-driven flush at low EPS             |
| `CHANNEL_CAP`         | 50000   | ~50 MB peak in-flight; blocks reader on CH lag |
| `STORE_RAW_DATA`      | true    | Enable for forensics; disable to save 40–70% storage |
| `OCSF_VALIDATE`       | true    | Set false for load testing only           |

## Swap

No swap is configured on this host (0B). With 15 GB RAM available this is acceptable,
but consider adding a 4 GB swapfile if OOM kills are observed under peak load:

```bash
fallocate -l 4G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

## Wazuh manager resource usage

Observed idle: ~3.1 GB RSS with 16 CPU cores.
Memory peak tracks with number of connected agents and FIM checks.
