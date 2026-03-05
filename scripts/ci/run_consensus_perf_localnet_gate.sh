#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCALNET_DIR="$ROOT_DIR/deployments/localnet"
cd "$ROOT_DIR"

# shellcheck disable=SC1091
source "$ROOT_DIR/consensus/ci/perf_baseline.sh"
# shellcheck disable=SC1091
source "$ROOT_DIR/consensus/ci/perf_thresholds.sh"

RUNS="${RUNS:-1}"
MEASURE_SECS="${PERF_MEASURE_SECS:-60}"
WARMUP_SECS="${PERF_WARMUP_SECS:-20}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$ROOT_DIR/artifacts/consensus-perf-localnet}"
LOADGEN_WORKERS="${LOADGEN_WORKERS:-12}"
LOADGEN_TX_TIMEOUT_SECS="${LOADGEN_TX_TIMEOUT_SECS:-20}"
SKIP_IMAGE_BUILD="${SKIP_IMAGE_BUILD:-0}"

mkdir -p "$ARTIFACTS_DIR"
SUMMARY_FILE="$ARTIFACTS_DIR/summary.tsv"
RESULT_FILE="$ARTIFACTS_DIR/result.env"
NOISE_FILE="$ARTIFACTS_DIR/noise_context.env"

{
  echo -e "scenario\truns\tpasses\tfails\tmedian_views_per_sec\tmedian_finalized_tps\tmedian_inclusion_rate\tmedian_latency_p95_ms\tmedian_latency_p99_ms\tmedian_warn_count\tmedian_error_count"
} > "$SUMMARY_FILE"

float_lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a < b) }'; }
float_gt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a > b) }'; }

median_from_file() {
  local file="$1"
  local count
  count="$(wc -l < "$file" | tr -d ' ')"
  if [[ "$count" == "0" ]]; then
    echo "0"
    return
  fi
  sort -n "$file" > "$file.sorted"
  if (( count % 2 == 1 )); then
    sed -n "$(((count + 1) / 2))p" "$file.sorted"
  else
    local left right
    left="$(sed -n "$((count / 2))p" "$file.sorted")"
    right="$(sed -n "$((count / 2 + 1))p" "$file.sorted")"
    awk -v a="$left" -v b="$right" 'BEGIN { printf("%.6f\n", (a+b)/2.0) }'
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 1
  fi
}

require_cmd docker
require_cmd curl
require_cmd awk
require_cmd sed
require_cmd grep
require_cmd cargo

dc() {
  docker compose -f "$LOCALNET_DIR/docker-compose.yml" -f "$LOCALNET_DIR/localnet.override.yml" "$@"
}

cleanup_stack() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
}

wait_for_http() {
  local url="$1"
  local timeout_secs="${2:-120}"
  local start
  start="$(date +%s)"
  while true; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    if (( "$(date +%s)" - start > timeout_secs )); then
      return 1
    fi
    sleep 1
  done
}

scrape_metric_from_port() {
  local port="$1"
  local metric="$2"
  curl -fsS "http://127.0.0.1:${port}/metrics" | awk -v m="$metric" '$1==m { print $2; exit }'
}

avg_current_view() {
  local ports=(9090 9092 9093 9094 9095 9096)
  local sum="0"
  local count=0
  local p val
  for p in "${ports[@]}"; do
    val="$(scrape_metric_from_port "$p" "consensus_current_view" || true)"
    if [[ -n "$val" ]]; then
      sum="$(awk -v a="$sum" -v b="$val" 'BEGIN { printf("%.6f", a+b) }')"
      count=$((count + 1))
    fi
  done
  if (( count == 0 )); then
    echo "0"
  else
    awk -v s="$sum" -v c="$count" 'BEGIN { printf("%.6f", s/c) }'
  fi
}

trap cleanup_stack EXIT
cleanup_stack

# Build docker image once per gate run unless caller explicitly skips it.
if [[ "$SKIP_IMAGE_BUILD" != "1" ]]; then
  require_cmd nix
  nix build .#dockerImage
  docker load < "$ROOT_DIR/result"
else
  if ! docker image inspect kairos-node:latest >/dev/null 2>&1; then
    echo "SKIP_IMAGE_BUILD=1 but kairos-node:latest image not found locally"
    exit 1
  fi
fi

if command -v nproc >/dev/null 2>&1; then
  cpu_count="$(nproc)"
else
  cpu_count="unknown"
fi
load_avg="$(cat /proc/loadavg 2>/dev/null || echo "unavailable")"
{
  echo "cpu_count=$cpu_count"
  echo "load_avg=$load_avg"
  echo "runs=$RUNS"
  echo "measure_secs=$MEASURE_SECS"
  echo "warmup_secs=$WARMUP_SECS"
  echo "loadgen_workers=$LOADGEN_WORKERS"
  echo "loadgen_tx_timeout_secs=$LOADGEN_TX_TIMEOUT_SECS"
} > "$NOISE_FILE"

scenario_dir="$ARTIFACTS_DIR/localnet_steady_state"
mkdir -p "$scenario_dir"

views_file="$scenario_dir/views_per_sec.values"
finalized_file="$scenario_dir/finalized_tps.values"
inclusion_file="$scenario_dir/inclusion_rate.values"
latency_p95_file="$scenario_dir/latency_p95_ms.values"
latency_p99_file="$scenario_dir/latency_p99_ms.values"
warn_file="$scenario_dir/warn_count.values"
error_file="$scenario_dir/error_count.values"

: > "$views_file"
: > "$finalized_file"
: > "$inclusion_file"
: > "$latency_p95_file"
: > "$latency_p99_file"
: > "$warn_file"
: > "$error_file"

passes=0
fails=0

for run in $(seq 1 "$RUNS"); do
  echo "=== localnet perf run=$run/$RUNS ==="
  run_dir="$scenario_dir/run-$run"
  mkdir -p "$run_dir"
  compose_log="$run_dir/compose.log"
  loadgen_log="$run_dir/loadgen.log"
  metrics_file="$run_dir/metrics.env"
  logs_file="$run_dir/validators.log"

  cleanup_stack
  (cd "$LOCALNET_DIR" && ./generate-keys.sh) > "$run_dir/generate-keys.log" 2>&1
  dc up -d > "$compose_log" 2>&1

  wait_for_http "http://127.0.0.1:9090/metrics" 180 || { echo "validator-0 metrics not ready"; fails=$((fails + 1)); continue; }
  wait_for_http "http://127.0.0.1:9092/metrics" 180 || { echo "validator-1 metrics not ready"; fails=$((fails + 1)); continue; }
  wait_for_http "http://127.0.0.1:9093/metrics" 180 || { echo "validator-2 metrics not ready"; fails=$((fails + 1)); continue; }
  wait_for_http "http://127.0.0.1:9094/metrics" 180 || { echo "validator-3 metrics not ready"; fails=$((fails + 1)); continue; }
  wait_for_http "http://127.0.0.1:9095/metrics" 180 || { echo "validator-4 metrics not ready"; fails=$((fails + 1)); continue; }
  wait_for_http "http://127.0.0.1:9096/metrics" 180 || { echo "validator-5 metrics not ready"; fails=$((fails + 1)); continue; }

  sleep "$WARMUP_SECS"
  start_view="$(avg_current_view)"

  set +e
  LOADGEN_DURATION_SECS="$MEASURE_SECS" \
  LOADGEN_WORKERS="$LOADGEN_WORKERS" \
  LOADGEN_TX_TIMEOUT_SECS="$LOADGEN_TX_TIMEOUT_SECS" \
  cargo run -p kairos-sdk --release --bin localnet-loadgen > "$loadgen_log" 2>&1
  loadgen_status=$?
  set -e

  end_view="$(avg_current_view)"
  views_per_sec="$(awk -v s="$start_view" -v e="$end_view" -v d="$MEASURE_SECS" 'BEGIN { if (d==0) print 0; else printf("%.6f", (e-s)/d) }')"

  dc logs --no-color validator-0 validator-1 validator-2 validator-3 validator-4 validator-5 > "$logs_file" 2>&1 || true
  warn_count="$(grep -E -c " WARN |\\bWARN\\b| level=warning|\"level\":\"WARN\"" "$logs_file" || true)"
  error_count="$(grep -E -c " ERRO |\\bERROR\\b| level=error|\"level\":\"ERRO\"" "$logs_file" || true)"

  metrics_line="$(grep 'LOADGEN_METRICS' "$loadgen_log" | tail -1 || true)"
  if (( loadgen_status != 0 )) || [[ -z "$metrics_line" ]]; then
    echo "run_verdict=fail reason=loadgen_failed status=$loadgen_status views_per_sec=$views_per_sec warn_count=$warn_count error_count=$error_count"
    fails=$((fails + 1))
    continue
  fi

  finalized_tps="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="finalized_tps"){print a[2]}}}' <<< "$metrics_line")"
  inclusion_rate="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="inclusion_rate"){print a[2]}}}' <<< "$metrics_line")"
  latency_p95_ms="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="latency_p95_ms"){print a[2]}}}' <<< "$metrics_line")"
  latency_p99_ms="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="latency_p99_ms"){print a[2]}}}' <<< "$metrics_line")"

  {
    echo "views_per_sec=$views_per_sec"
    echo "finalized_tps=$finalized_tps"
    echo "inclusion_rate=$inclusion_rate"
    echo "latency_p95_ms=$latency_p95_ms"
    echo "latency_p99_ms=$latency_p99_ms"
    echo "warn_count=$warn_count"
    echo "error_count=$error_count"
  } > "$metrics_file"

  echo "$views_per_sec" >> "$views_file"
  echo "$finalized_tps" >> "$finalized_file"
  echo "$inclusion_rate" >> "$inclusion_file"
  echo "$latency_p95_ms" >> "$latency_p95_file"
  echo "$latency_p99_ms" >> "$latency_p99_file"
  echo "$warn_count" >> "$warn_file"
  echo "$error_count" >> "$error_file"

  passes=$((passes + 1))
  echo "run_verdict=pass views_per_sec=$views_per_sec finalized_tps=$finalized_tps inclusion_rate=$inclusion_rate latency_p95_ms=$latency_p95_ms latency_p99_ms=$latency_p99_ms warn_count=$warn_count error_count=$error_count"
done

median_views_per_sec="$(median_from_file "$views_file")"
median_finalized_tps="$(median_from_file "$finalized_file")"
median_inclusion_rate="$(median_from_file "$inclusion_file")"
median_latency_p95_ms="$(median_from_file "$latency_p95_file")"
median_latency_p99_ms="$(median_from_file "$latency_p99_file")"
median_warn_count="$(median_from_file "$warn_file")"
median_error_count="$(median_from_file "$error_file")"

echo -e "localnet_steady_state\t$RUNS\t$passes\t$fails\t$median_views_per_sec\t$median_finalized_tps\t$median_inclusion_rate\t$median_latency_p95_ms\t$median_latency_p99_ms\t$median_warn_count\t$median_error_count" >> "$SUMMARY_FILE"

regression_failures=0

views_rel_floor="$(awk -v b="$BASELINE_STEADY_STATE_VIEWS_PER_SEC" -v p="$MAX_DROP_VIEWS_PER_SEC_PCT" 'BEGIN { printf("%.6f\n", b*(1.0-p)) }')"
views_abs_floor="$(awk -v b="$BASELINE_STEADY_STATE_VIEWS_PER_SEC" -v d="$MAX_DROP_VIEWS_PER_SEC_ABS" 'BEGIN { printf("%.6f\n", b-d) }')"
if float_lt "$median_views_per_sec" "$views_rel_floor" && float_lt "$median_views_per_sec" "$views_abs_floor"; then
  echo "REGRESSION views_per_sec median=$median_views_per_sec baseline=$BASELINE_STEADY_STATE_VIEWS_PER_SEC rel_floor=$views_rel_floor abs_floor=$views_abs_floor"
  regression_failures=$((regression_failures + 1))
fi
if float_lt "$median_views_per_sec" "$ABS_MIN_VIEWS_PER_SEC"; then
  echo "HARD_FLOOR views_per_sec median=$median_views_per_sec min=$ABS_MIN_VIEWS_PER_SEC"
  regression_failures=$((regression_failures + 1))
fi

finalized_rel_floor="$(awk -v b="$BASELINE_STEADY_STATE_FINALIZED_TPS" -v p="$MAX_DROP_FINALIZED_TPS_PCT" 'BEGIN { printf("%.6f\n", b*(1.0-p)) }')"
finalized_abs_floor="$(awk -v b="$BASELINE_STEADY_STATE_FINALIZED_TPS" -v d="$MAX_DROP_FINALIZED_TPS_ABS" 'BEGIN { printf("%.6f\n", b-d) }')"
if float_lt "$median_finalized_tps" "$finalized_rel_floor" && float_lt "$median_finalized_tps" "$finalized_abs_floor"; then
  echo "REGRESSION finalized_tps median=$median_finalized_tps baseline=$BASELINE_STEADY_STATE_FINALIZED_TPS rel_floor=$finalized_rel_floor abs_floor=$finalized_abs_floor"
  regression_failures=$((regression_failures + 1))
fi
if float_lt "$median_finalized_tps" "$ABS_MIN_FINALIZED_TPS"; then
  echo "HARD_FLOOR finalized_tps median=$median_finalized_tps min=$ABS_MIN_FINALIZED_TPS"
  regression_failures=$((regression_failures + 1))
fi

inclusion_rel_floor="$(awk -v b="$BASELINE_STEADY_STATE_INCLUSION_RATE" -v p="$MAX_DROP_INCLUSION_RATE_PCT" 'BEGIN { printf("%.6f\n", b*(1.0-p)) }')"
inclusion_abs_floor="$(awk -v b="$BASELINE_STEADY_STATE_INCLUSION_RATE" -v d="$MAX_DROP_INCLUSION_RATE_ABS" 'BEGIN { printf("%.6f\n", b-d) }')"
if float_lt "$median_inclusion_rate" "$inclusion_rel_floor" && float_lt "$median_inclusion_rate" "$inclusion_abs_floor"; then
  echo "REGRESSION inclusion_rate median=$median_inclusion_rate baseline=$BASELINE_STEADY_STATE_INCLUSION_RATE rel_floor=$inclusion_rel_floor abs_floor=$inclusion_abs_floor"
  regression_failures=$((regression_failures + 1))
fi
if float_lt "$median_inclusion_rate" "$ABS_MIN_INCLUSION_RATE"; then
  echo "HARD_FLOOR inclusion_rate median=$median_inclusion_rate min=$ABS_MIN_INCLUSION_RATE"
  regression_failures=$((regression_failures + 1))
fi

p95_rel_ceil="$(awk -v b="$BASELINE_STEADY_STATE_LATENCY_P95_MS" -v p="$MAX_INCREASE_LATENCY_P95_PCT" 'BEGIN { printf("%.6f\n", b*(1.0+p)) }')"
p95_abs_ceil="$(awk -v b="$BASELINE_STEADY_STATE_LATENCY_P95_MS" -v d="$MAX_INCREASE_LATENCY_P95_ABS_MS" 'BEGIN { printf("%.6f\n", b+d) }')"
if float_gt "$median_latency_p95_ms" "$p95_rel_ceil" && float_gt "$median_latency_p95_ms" "$p95_abs_ceil"; then
  echo "REGRESSION latency_p95_ms median=$median_latency_p95_ms baseline=$BASELINE_STEADY_STATE_LATENCY_P95_MS rel_ceil=$p95_rel_ceil abs_ceil=$p95_abs_ceil"
  regression_failures=$((regression_failures + 1))
fi
if float_gt "$median_latency_p95_ms" "$ABS_MAX_LATENCY_P95_MS"; then
  echo "HARD_CEIL latency_p95_ms median=$median_latency_p95_ms max=$ABS_MAX_LATENCY_P95_MS"
  regression_failures=$((regression_failures + 1))
fi

p99_rel_ceil="$(awk -v b="$BASELINE_STEADY_STATE_LATENCY_P99_MS" -v p="$MAX_INCREASE_LATENCY_P99_PCT" 'BEGIN { printf("%.6f\n", b*(1.0+p)) }')"
p99_abs_ceil="$(awk -v b="$BASELINE_STEADY_STATE_LATENCY_P99_MS" -v d="$MAX_INCREASE_LATENCY_P99_ABS_MS" 'BEGIN { printf("%.6f\n", b+d) }')"
if float_gt "$median_latency_p99_ms" "$p99_rel_ceil" && float_gt "$median_latency_p99_ms" "$p99_abs_ceil"; then
  echo "REGRESSION latency_p99_ms median=$median_latency_p99_ms baseline=$BASELINE_STEADY_STATE_LATENCY_P99_MS rel_ceil=$p99_rel_ceil abs_ceil=$p99_abs_ceil"
  regression_failures=$((regression_failures + 1))
fi
if float_gt "$median_latency_p99_ms" "$ABS_MAX_LATENCY_P99_MS"; then
  echo "HARD_CEIL latency_p99_ms median=$median_latency_p99_ms max=$ABS_MAX_LATENCY_P99_MS"
  regression_failures=$((regression_failures + 1))
fi

{
  echo "passes=$passes"
  echo "fails=$fails"
  echo "regression_failures=$regression_failures"
  echo "median_views_per_sec=$median_views_per_sec"
  echo "median_finalized_tps=$median_finalized_tps"
  echo "median_inclusion_rate=$median_inclusion_rate"
  echo "median_latency_p95_ms=$median_latency_p95_ms"
  echo "median_latency_p99_ms=$median_latency_p99_ms"
  echo "median_warn_count=$median_warn_count"
  echo "median_error_count=$median_error_count"
} > "$RESULT_FILE"

echo ""
echo "=== Localnet perf summary ==="
cat "$SUMMARY_FILE"

if (( fails > 0 )); then
  echo "localnet perf gate failed: scenario runs failed ($fails/$RUNS)"
  exit 1
fi
if (( regression_failures > 0 )); then
  echo "localnet perf gate failed: regression_failures=$regression_failures"
  exit 1
fi

echo "localnet perf gate passed"
