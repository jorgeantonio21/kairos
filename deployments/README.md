# Kairos Local Observability Stack

This directory contains a Docker Compose deployment for running a Kairos
validator node alongside **Prometheus**, **Loki**, and **Grafana** for local
metrics collection, log aggregation, and visualization.

## Architecture

```
kairos-node (stdout → JSON logs, :9090 metrics)
      │                          │
      ▼                          ▼
  Prometheus (:9091)          Alloy
      │         discovers & tails Docker logs
      │                          │
      │                          ▼
      │                    Loki (:3100)
      │                          │
      └──────────┬───────────────┘
                 ▼
          Grafana (:3000)
```

| Service        | Image                         | Exposed Port |
|----------------|-------------------------------|--------------|
| `kairos-node`  | Built via `nix build .#dockerImage` | `9090` (metrics), `50051` (gRPC), `9000` (P2P) |
| `prometheus`   | `prom/prometheus:v3.3.0`      | `9091` → container `9090` |
| `loki`         | `grafana/loki:3.4.2`          | `3100` |
| `alloy`        | `grafana/alloy:v1.8.3`        | — (internal) |
| `grafana`      | `grafana/grafana:11.6.0`      | `3000` |

## Quick Start

```bash
# From the repository root — build the Docker image via Nix and load it
nix build .#dockerImage && docker load < result

# Start the stack
docker compose -f deployments/docker-compose.yml up
```

Wait for all five services to become healthy, then open
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

## Viewing Logs in Grafana

Container logs from `kairos-node` (and all other services) are collected by
**Grafana Alloy** and stored in **Loki**. The node outputs structured JSON via
`slog`, so log fields like `level` and `msg` are automatically extracted.

### How the Log Pipeline Works

```
kairos-node (stdout)
      │  structured JSON via slog_json
      ▼
  Docker log driver
      │  wraps each line in {"log": "...", "stream": "...", "time": "..."}
      ▼
  Alloy (discovery.docker → loki.source.docker)
      │  auto-discovers containers via Docker socket
      │  strips the Docker JSON envelope
      ▼
  Alloy (loki.process)
      │  parses the slog JSON payload
      │  extracts "level" as a Loki label
      ▼
  Loki (:3100)
      │  indexes & stores log streams
      ▼
  Grafana (Explore / Dashboards)
```

Alloy automatically discovers **every container** in the Compose stack. Each
container becomes a separate log stream in Loki, labelled with Docker metadata
(container name, image, compose service, etc.).

### Querying Logs in the Explore View

1. Open **<http://localhost:3000>**.
2. Click the **compass icon** (Explore) in the left sidebar.
3. In the **datasource dropdown** at the top, select **Loki**.
4. Switch to **Code** mode (top-right of the query editor) for raw LogQL, or
   use **Builder** mode for point-and-click filtering.
5. Enter a LogQL query (see examples below).
6. Click **Run query** (or press `Shift+Enter`).
7. Results appear as a **log stream** — click any log line to expand it and see
   all parsed JSON fields.

> **Tip:** Toggle between **Logs**, **Table**, and **Graph** views using the
> buttons above the results to explore the data differently.

### LogQL Query Reference

LogQL has two stages: a **stream selector** `{...}` to pick which logs to
scan, and an optional **pipeline** `| ...` to filter, parse, and transform.

#### Stream Selectors

```logql
{job="kairos"}                            # all containers in the kairos job
{container_name="deployments-kairos-node-1"}  # specific container
{container_name=~".*kairos.*"}            # regex match on container name
```

#### Filtering by Log Content

```logql
{job="kairos"} |= "finalized"            # lines containing "finalized"
{job="kairos"} !~ "debug|trace"           # exclude debug/trace lines
{job="kairos"} |= "ConsensusEngine"       # consensus engine messages
{job="kairos"} |= "P2P"                   # P2P layer messages
{job="kairos"} |= "gRPC"                  # gRPC server messages
{job="kairos"} |= "bootstrap"             # bootstrap phase logs
```

#### Filtering by slog JSON Fields

Since the node emits structured JSON, you can parse and filter on any field:

```logql
# Parse JSON and filter by level
{job="kairos"} | json | level="INFO"
{job="kairos"} | json | level="ERROR"
{job="kairos"} | json | level=~"ERROR|WARNING"

# Filter by message content after parsing
{job="kairos"} | json | msg=~".*finalized.*"

# Filter by custom slog key-value pairs
# (e.g. slog::info!(logger, "Block finalized"; "view" => 42))
{job="kairos"} | json | view="42"
```

#### Log-based Metrics

You can turn log queries into time-series metrics:

```logql
# Error rate over time
rate({job="kairos"} | json | level="ERROR" [1m])

# Count of finalized blocks per minute
count_over_time({job="kairos"} |= "finalized" [1m])

# Ratio of errors to total logs
sum(rate({job="kairos"} | json | level="ERROR" [5m]))
  /
sum(rate({job="kairos"} [5m]))
```

### Filtering by Component (Crate)

The `consensus`, `p2p`, `rpc`, and `grpc-client` crates all log through the
same `slog::Logger`. Since they all run inside the same `kairos-node`
container, they share the same log stream. To isolate logs from a specific
component, filter by keywords that appear in that component's log messages:

| Component     | Example Filter |
|---------------|----------------|
| **consensus** | `{job="kairos"} \|= "ConsensusEngine"` or `\|= "view"` or `\|= "finalized"` |
| **p2p**       | `{job="kairos"} \|= "P2P"` or `\|= "bootstrap"` or `\|= "peer"` |
| **rpc**       | `{job="kairos"} \|= "RPC"` or `\|= "gRPC server"` or `\|= "Block syncer"` |
| **grpc-client** | `{job="kairos"} \|= "gRPC"` or `\|= "transaction"` |

> **Tip:** If you want first-class label filtering per component, you can add
> a slog key like `"component" => "consensus"` to each crate's root logger.
> This will appear as a top-level JSON field and can be filtered with
> `| json | component="consensus"`.

### Creating a Logs Dashboard Panel

1. Navigate to **Dashboards** → **New** → **New Dashboard**.
2. Click **Add visualization**.
3. Select the **Loki** datasource.
4. Enter a LogQL query, e.g.:
   ```logql
   {job="kairos"} | json | level=~"ERROR|WARNING"
   ```
5. In the **Panel options** sidebar (right side):
   - Set the **Title** (e.g. `Node Errors & Warnings`).
   - Under **Visualization**, pick **Logs** for a log stream view, or
     **Time series** for log-based metrics.
6. For a **Logs** panel, configure:
   - **Show time** — display timestamps.
   - **Wrap lines** — wrap long log lines.
   - **Sort order** — `Descending` to show newest first.
   - **Deduplication** — set to `Exact` or `Signature` to collapse
     repeated entries.
   - **Enable log details** — shows parsed JSON fields when clicking a line.
7. Click **Apply**, then **Save dashboard**.

### Building a Mixed Metrics + Logs Dashboard

You can combine Prometheus metrics and Loki logs in a single dashboard:

1. Open an existing dashboard (e.g. **Kairos Consensus**) or create a new one.
2. Click **Add** → **Visualization**.
3. Select the **Loki** datasource and enter a log-based metric query:
   ```logql
   rate({job="kairos"} | json | level="ERROR" [1m])
   ```
4. Place it alongside the existing Prometheus panels for a unified view of
   metrics and logs.

You can also **link panels** for drill-down: click a spike in a metric panel,
then use **Split view** (`Ctrl/Cmd + Shift + E` in Explore) to query Loki
for the same time range to see what happened in the logs.

### Persisting Log Dashboards

Dashboards created through the UI are stored in the `grafana-data` Docker
volume and will survive `docker compose restart`. However, they are lost on
`docker compose down` (which removes volumes).

To persist permanently, export the dashboard as JSON:

1. Open the dashboard → **Share** (top bar) → **Export** → **Save to file**.
2. Place the JSON file in `grafana/dashboards/`.
3. It will be auto-provisioned on the next `docker compose up`.

### slog JSON Field Reference

The `slog_json` drain produces log lines with these standard fields:

| Field   | Description                  | Example          |
|---------|------------------------------|------------------|
| `msg`   | Log message                  | `"Block finalized"` |
| `level` | Severity (INFO, WARN, etc.)  | `"INFO"`         |
| `ts`    | Timestamp                    | `"2026-02-21T..."` |

Additional key-value pairs from `slog::info!(logger, "msg"; "key" => val)`
appear as top-level JSON fields and can be filtered with
`| json | key="value"`.

### Loki API

Loki also exposes a REST API at **<http://localhost:3100>** for programmatic
access:

```bash
# Query logs via the API
curl -s 'http://localhost:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="kairos"}' \
  --data-urlencode 'limit=10' | jq .

# Check available labels
curl -s 'http://localhost:3100/loki/api/v1/labels' | jq .

# Check values for a specific label
curl -s 'http://localhost:3100/loki/api/v1/label/level/values' | jq .
```

## Directory Layout

```
deployments/
├── README.md                              ← you are here
├── docker-compose.yml                     ← orchestrates all services
├── config/
│   └── node.toml                          ← validator node configuration
├── prometheus/
│   └── prometheus.yml                     ← scrape targets & intervals
├── loki/
│   └── loki.yml                           ← Loki storage & retention config
├── alloy/
│   └── config.alloy                       ← Alloy log collection & pipeline config
└── grafana/
    ├── dashboards/
    │   └── consensus.json                 ← pre-provisioned Consensus dashboard
    └── provisioning/
        ├── dashboards/
        │   └── dashboards.yml             ← auto-load dashboards from disk
        └── datasources/
            └── prometheus.yml             ← Prometheus + Loki datasources
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
