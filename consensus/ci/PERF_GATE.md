# Consensus Performance Gate

This gate prevents performance regressions using the real 6-validator localnet cluster:

- Localnet stack: `deployments/localnet/docker-compose.yml` (+ `localnet.override.yml`)
- TX load source: `cargo run -p kairos-sdk --release --bin localnet-loadgen`
- Gate script: `scripts/ci/run_consensus_perf_localnet_gate.sh`
  - Optional local shortcut: `SKIP_IMAGE_BUILD=1` (requires existing `kairos-node:latest`)

## Metrics

- `views_per_sec` (average validator view delta / measurement seconds)
- `finalized_tps`
- `inclusion_rate`
- `latency_p95_ms`
- `latency_p99_ms`

## Noise controls

- Warmup window excluded (`PERF_WARMUP_SECS`)
- Repeated runs with median aggregation (`RUNS=3` PR, `RUNS=5` nightly)
- Relative + absolute regression checks (prevents noise-induced failures)
- Hard floors/caps for minimum acceptable behavior
- Captures runner noise context (`cpu_count`, `load_avg`) in artifacts

## Baseline and thresholds

- Baseline: `consensus/ci/perf_baseline.sh`
- Thresholds: `consensus/ci/perf_thresholds.sh`

## Calibrating a new baseline

1. Run calibration profile on a stable localnet runner:
   `RUNS=10 PERF_MEASURE_SECS=120 PERF_WARMUP_SECS=20 bash scripts/ci/run_consensus_perf_localnet_gate.sh`
2. Review `artifacts/consensus-perf-localnet/summary.tsv`.
3. Update `perf_baseline.sh` intentionally in one commit.
4. Keep thresholds unchanged unless variance data justifies it.
