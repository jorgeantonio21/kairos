#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# shellcheck disable=SC1091
source "$ROOT_DIR/consensus/ci/log_policy.sh"

RUNS="${RUNS:-3}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$ROOT_DIR/artifacts/consensus-e2e}"
RUST_LOG_LEVEL="${RUST_LOG_LEVEL:-info}"
CONSENSUS_TEST_FILTER="${CONSENSUS_TEST_FILTER:-}"

ALL_TESTS=(
  "test_e2e_consensus_happy_path"
  "test_e2e_consensus_continuous_load"
  "test_e2e_consensus_with_crashed_replica"
  "test_e2e_consensus_with_equivocating_leader"
  "test_e2e_consensus_with_persistent_equivocating_leader"
  "test_e2e_consensus_functional_blockchain"
  "test_e2e_consensus_invalid_tx_rejection"
  "test_e2e_consensus_with_invalid_block_from_leader"
  "test_e2e_consensus_with_true_equivocation"
)

TESTS=()
if [[ -n "$CONSENSUS_TEST_FILTER" ]]; then
  TESTS=("$CONSENSUS_TEST_FILTER")
else
  TESTS=("${ALL_TESTS[@]}")
fi

mkdir -p "$ARTIFACTS_DIR"
SUMMARY_TSV="$ARTIFACTS_DIR/summary.tsv"
{
  echo -e "test\truns\tpassed\tfailed\tfatal_hits\tbudget_violations"
} > "$SUMMARY_TSV"

check_fatal_patterns() {
  local logfile="$1"
  local hits=0
  local pattern
  for pattern in "${FATAL_PATTERNS[@]}"; do
    local count
    count="$(grep -F -c "$pattern" "$logfile" || true)"
    if (( count > 0 )); then
      echo "FATAL_PATTERN pattern=\"$pattern\" count=$count file=\"$logfile\"" >&2
      hits=$((hits + count))
    fi
  done
  echo "$hits"
}

check_budget_violations() {
  local logfile="$1"
  local test_name="$2"
  local violations=0
  local pattern

  for pattern in "${!PATTERN_BUDGETS[@]}"; do
    local count
    count="$(grep -F -c "$pattern" "$logfile" || true)"
    local budget="${PATTERN_BUDGETS[$pattern]}"

    # Strict tests should not emit some fault-oriented recoverable patterns at all.
    if test_in_array "$test_name" "${STRICT_TESTS[@]}"; then
      if [[ "$pattern" == "Received nullification for past M-notarized view" ]] ||
         [[ "$pattern" == "Cascading nullification from view" ]] ||
         [[ "$pattern" == "Nullifying range from view" ]]; then
        budget=0
      fi
    fi

    if (( count > budget )); then
      echo "BUDGET_VIOLATION pattern=\"$pattern\" count=$count budget=$budget file=\"$logfile\"" >&2
      violations=$((violations + 1))
    fi
  done

  echo "$violations"
}

total_failures=0
echo "Consensus e2e repeated run"
echo "runs_per_test=$RUNS artifacts_dir=$ARTIFACTS_DIR rust_log=$RUST_LOG_LEVEL"

for test_name in "${TESTS[@]}"; do
  test_dir="$ARTIFACTS_DIR/$test_name"
  mkdir -p "$test_dir"

  test_passed=0
  test_failed=0
  test_fatal_hits=0
  test_budget_violations=0

  for run_index in $(seq 1 "$RUNS"); do
    logfile="$test_dir/run-${run_index}.log"
    meta_file="$test_dir/run-${run_index}.meta"

    echo ""
    echo "=== test=$test_name run=$run_index/$RUNS ==="

    set +e
    RUST_LOG="$RUST_LOG_LEVEL" cargo test --package consensus --lib "$test_name" -- --ignored --nocapture \
      >"$logfile" 2>&1
    status=$?
    set -e

    fatal_hits="$(check_fatal_patterns "$logfile")"
    budget_violations="$(check_budget_violations "$logfile" "$test_name")"

    if (( status == 0 )) && (( fatal_hits == 0 )) && (( budget_violations == 0 )); then
      test_passed=$((test_passed + 1))
      verdict="pass"
    else
      test_failed=$((test_failed + 1))
      total_failures=$((total_failures + 1))
      verdict="fail"
    fi

    test_fatal_hits=$((test_fatal_hits + fatal_hits))
    test_budget_violations=$((test_budget_violations + budget_violations))

    warn_lines="$(grep -E -c "(WARN|warning)" "$logfile" || true)"
    error_lines="$(grep -E -c "(ERRO|ERROR|error)" "$logfile" || true)"

    {
      echo "test=$test_name"
      echo "run=$run_index"
      echo "status=$status"
      echo "warn_lines=$warn_lines"
      echo "error_lines=$error_lines"
      echo "fatal_hits=$fatal_hits"
      echo "budget_violations=$budget_violations"
      echo "verdict=$verdict"
    } > "$meta_file"

    echo "run_verdict=$verdict cargo_status=$status warn_lines=$warn_lines error_lines=$error_lines fatal_hits=$fatal_hits budget_violations=$budget_violations"
  done

  echo -e "$test_name\t$RUNS\t$test_passed\t$test_failed\t$test_fatal_hits\t$test_budget_violations" >> "$SUMMARY_TSV"
done

echo ""
echo "=== Repeated e2e summary ==="
cat "$SUMMARY_TSV"

if (( total_failures > 0 )); then
  echo "consensus e2e repeated run failed: total_failures=$total_failures"
  exit 1
fi

echo "consensus e2e repeated run passed"
