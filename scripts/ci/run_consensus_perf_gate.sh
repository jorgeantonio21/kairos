#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# shellcheck disable=SC1091
source "$ROOT_DIR/consensus/ci/perf_baseline.sh"
# shellcheck disable=SC1091
source "$ROOT_DIR/consensus/ci/perf_thresholds.sh"

RUNS="${RUNS:-3}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$ROOT_DIR/artifacts/consensus-perf}"
RUST_LOG_LEVEL="${RUST_LOG_LEVEL:-info}"
SCENARIO_TEST="${SCENARIO_TEST:-test_perf_consensus_steady_state}"
PERF_TEST_DURATION_SECS="${PERF_TEST_DURATION_SECS:-30}"
PERF_TEST_WARMUP_SECS="${PERF_TEST_WARMUP_SECS:-10}"
PERF_TEST_TX_INTERVAL_MS="${PERF_TEST_TX_INTERVAL_MS:-100}"
PERF_TEST_TX_BATCH_SIZE="${PERF_TEST_TX_BATCH_SIZE:-1}"

mkdir -p "$ARTIFACTS_DIR"
SUMMARY_FILE="$ARTIFACTS_DIR/summary.tsv"
RESULT_FILE="$ARTIFACTS_DIR/result.env"

{
  echo -e "scenario\truns\tpasses\tfails\tmedian_views_per_sec\tmedian_finalized_tps\tmedian_inclusion_rate\tmedian_latency_p95_ms\tmedian_latency_p99_ms"
} > "$SUMMARY_FILE"

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
  echo "duration_secs=$PERF_TEST_DURATION_SECS"
  echo "warmup_secs=$PERF_TEST_WARMUP_SECS"
  echo "tx_interval_ms=$PERF_TEST_TX_INTERVAL_MS"
  echo "tx_batch_size=$PERF_TEST_TX_BATCH_SIZE"
} > "$ARTIFACTS_DIR/noise_context.env"

parse_metric() {
  local line="$1"
  local key="$2"
  awk -v k="$key" '{
    for (i=1;i<=NF;i++) {
      split($i, a, "=")
      if (a[1] == k) {
        print a[2]
      }
    }
  }' <<< "$line"
}

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

float_lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a < b) }'; }
float_gt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a > b) }'; }

scenario_dir="$ARTIFACTS_DIR/steady_state"
mkdir -p "$scenario_dir"
passes=0
fails=0

views_file="$scenario_dir/views_per_sec.values"
finalized_file="$scenario_dir/finalized_tps.values"
inclusion_file="$scenario_dir/inclusion_rate.values"
latency_p95_file="$scenario_dir/latency_p95_ms.values"
latency_p99_file="$scenario_dir/latency_p99_ms.values"
: > "$views_file"
: > "$finalized_file"
: > "$inclusion_file"
: > "$latency_p95_file"
: > "$latency_p99_file"

for run in $(seq 1 "$RUNS"); do
  logfile="$scenario_dir/run-$run.log"
  metrics_file="$scenario_dir/run-$run.metrics"
  echo "=== perf scenario=steady_state run=$run/$RUNS ==="

  set +e
  RUST_LOG="$RUST_LOG_LEVEL" \
  PERF_TEST_DURATION_SECS="$PERF_TEST_DURATION_SECS" \
  PERF_TEST_WARMUP_SECS="$PERF_TEST_WARMUP_SECS" \
  PERF_TEST_TX_INTERVAL_MS="$PERF_TEST_TX_INTERVAL_MS" \
  PERF_TEST_TX_BATCH_SIZE="$PERF_TEST_TX_BATCH_SIZE" \
  cargo test --package consensus --lib "$SCENARIO_TEST" -- --ignored --nocapture > "$logfile" 2>&1
  status=$?
  set -e

  if (( status != 0 )); then
    fails=$((fails + 1))
    echo "run_verdict=fail cargo_status=$status"
    continue
  fi

  metrics_line="$(grep 'PERF_METRICS' "$logfile" | tail -1 || true)"
  if [[ -z "$metrics_line" ]]; then
    fails=$((fails + 1))
    echo "run_verdict=fail reason=no_metrics_line"
    continue
  fi

  views_per_sec="$(parse_metric "$metrics_line" "views_per_sec")"
  finalized_tps="$(parse_metric "$metrics_line" "finalized_tps")"
  inclusion_rate="$(parse_metric "$metrics_line" "inclusion_rate")"
  latency_p95_ms="$(parse_metric "$metrics_line" "latency_p95_ms")"
  latency_p99_ms="$(parse_metric "$metrics_line" "latency_p99_ms")"

  {
    echo "views_per_sec=$views_per_sec"
    echo "finalized_tps=$finalized_tps"
    echo "inclusion_rate=$inclusion_rate"
    echo "latency_p95_ms=$latency_p95_ms"
    echo "latency_p99_ms=$latency_p99_ms"
  } > "$metrics_file"

  echo "$views_per_sec" >> "$views_file"
  echo "$finalized_tps" >> "$finalized_file"
  echo "$inclusion_rate" >> "$inclusion_file"
  echo "$latency_p95_ms" >> "$latency_p95_file"
  echo "$latency_p99_ms" >> "$latency_p99_file"

  passes=$((passes + 1))
  echo "run_verdict=pass views_per_sec=$views_per_sec finalized_tps=$finalized_tps inclusion_rate=$inclusion_rate latency_p95_ms=$latency_p95_ms latency_p99_ms=$latency_p99_ms"
done

median_views_per_sec="$(median_from_file "$views_file")"
median_finalized_tps="$(median_from_file "$finalized_file")"
median_inclusion_rate="$(median_from_file "$inclusion_file")"
median_latency_p95_ms="$(median_from_file "$latency_p95_file")"
median_latency_p99_ms="$(median_from_file "$latency_p99_file")"

echo -e "steady_state\t$RUNS\t$passes\t$fails\t$median_views_per_sec\t$median_finalized_tps\t$median_inclusion_rate\t$median_latency_p95_ms\t$median_latency_p99_ms" >> "$SUMMARY_FILE"

regression_failures=0

# Higher-is-better metrics (fail when both relative and absolute regressions are exceeded)
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

# Lower-is-better metrics
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
} > "$RESULT_FILE"

echo ""
echo "=== Perf summary ==="
cat "$SUMMARY_FILE"

if (( fails > 0 )); then
  echo "perf gate failed: scenario runs failed ($fails/$RUNS)"
  exit 1
fi
if (( regression_failures > 0 )); then
  echo "perf gate failed: regression_failures=$regression_failures"
  exit 1
fi

echo "perf gate passed"
