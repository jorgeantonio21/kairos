# Kairos Local Observability Stack

This directory contains a Docker Compose deployment for running a Kairos
validator node alongside **Prometheus** and **Grafana** for local metrics
collection and visualization.

## Architecture

```
kairos-node (:9090 metrics)
      │
      ▼
  Prometheus (:9091)  ◄── scrapes /metrics every 5 s
      │
      ▼
   Grafana (:3000)    ◄── queries Prometheus datasource
```

| Service        | Image                       | Exposed Port |
|----------------|-----------------------------|--------------|
| `kairos-node`  | Built from `../Dockerfile`  | `9090` (metrics), `50051` (gRPC), `9000` (P2P) |
| `prometheus`   | `prom/prometheus:v3.3.0`    | `9091` → container `9090` |
| `grafana`      | `grafana/grafana:11.6.0`    | `3000` |

## Quick Start

```bash
# From the repository root
docker compose -f deployments/docker-compose.yml up --build
```

Wait for all three services to become healthy, then open
**<http://localhost:3000>** in your browser.

## Accessing Grafana

| Field    | Value   |
|----------|---------|
| URL      | <http://localhost:3000> |
| Username | `admin` |
| Password | `admin` |

> Anonymous read-only access is enabled by default
> (`GF_AUTH_ANONYMOUS_ENABLED=true`), so dashboards are visible without
> logging in.

## Viewing Prometheus Metrics in Grafana

### Pre-provisioned Dashboard

A **Kairos Consensus** dashboard is automatically provisioned on startup.
No manual import is required.

1. Open **<http://localhost:3000>**.
2. Navigate to the sidebar → **Dashboards** → **Kairos** folder.
3. Click **Kairos Consensus**.

The dashboard shows the following panels:

| Panel | Type | Metric(s) |
|-------|------|-----------|
| Current View | Stat | `consensus_current_view` |
| Finalized View | Stat | `consensus_finalized_view` |
| Views Since Finalization | Gauge | `consensus_views_since_finalization` |
| Blocks Finalized | Time series | `rate(consensus_blocks_finalized_total[1m])` |
| Finalization Latency | Time series | `consensus_finalization_latency_seconds` (p50, p99) |
| Nullification Rate | Time series | `rate(consensus_nullifications_total[1m])` |
| Cascade Nullifications | Time series | `rate(consensus_cascade_nullifications_total[1m])` |
| Messages by Type | Stacked time series | `rate(consensus_messages_processed_total[1m])` |
| Message Processing Latency p99 | Time series | `consensus_message_processing_duration_seconds` (p99) |
| Mempool Pool Sizes | Time series | `consensus_mempool_pending_count`, `consensus_mempool_queued_count` |
| Transaction Throughput | Time series | `rate(consensus_transactions_received_total[1m])` |
| Ring Buffer Utilization | Time series | `consensus_ring_buffer_utilization` (by channel) |
| Tick Duration p99 | Time series | `consensus_tick_duration_seconds` (p99) |

### Exploring Metrics Manually

You can also query any metric directly from the Grafana **Explore** view:

1. Open the sidebar → **Explore**.
2. Make sure the **Prometheus** datasource is selected (it is the default).
3. Enter a PromQL query, for example:
   ```promql
   rate(consensus_blocks_finalized_total[1m])
   ```
4. Click **Run query** to see the result as a graph or table.

> **Tip:** Type `consensus_` in the metric browser to auto-complete all
> available Kairos metrics.

### Creating a New Dashboard

1. Sidebar → **Dashboards** → **New** → **New Dashboard**.
2. Click **Add visualization**.
3. Select the **Prometheus** datasource.
4. Write a PromQL query in the **Metrics browser** (e.g.
   `histogram_quantile(0.99, rate(consensus_tick_duration_seconds_bucket[5m]))`).
5. Customize the panel title, axes, and thresholds in the right-hand panel
   options.
6. Click **Apply**, then **Save dashboard**.

To persist the dashboard across `docker compose down` / `up` cycles, export
it as JSON (**Share → Export → Save to file**) and place it in
`grafana/dashboards/`. It will be picked up automatically on the next
restart.

### Raw Prometheus UI

Prometheus itself exposes a query UI at **<http://localhost:9091>** where
you can test PromQL expressions before adding them to Grafana.

## Directory Layout

```
deployments/
├── README.md                              ← you are here
├── Dockerfile                             ← multi-stage build for kairos-node
├── docker-compose.yml                     ← orchestrates all services
├── config/
│   └── node.toml                          ← validator node configuration
├── prometheus/
│   └── prometheus.yml                     ← scrape targets & intervals
└── grafana/
    ├── dashboards/
    │   └── consensus.json                 ← pre-provisioned Consensus dashboard
    └── provisioning/
        ├── dashboards/
        │   └── dashboards.yml             ← auto-load dashboards from disk
        └── datasources/
            └── prometheus.yml             ← Prometheus datasource definition
```

## Adding New Scrape Targets

Edit `prometheus/prometheus.yml` to add more targets under `scrape_configs`:

```yaml
scrape_configs:
  - job_name: kairos
    static_configs:
      - targets:
          - kairos-node:9090
          - another-node:9090    # ← add here
```

Restart the stack for changes to take effect:

```bash
docker compose -f deployments/docker-compose.yml restart prometheus
```
