#!/usr/bin/env bash

# Fatal log patterns: if found in any run, fail immediately.
FATAL_PATTERNS=(
  "Consensus engine thread error for replica"
  "CRITICAL: Local vote signing failed verification with own PK"
  "thread '"
  "panicked at"
)

# Patterns that indicate protocol-recoverable behavior.
RECOVERABLE_PATTERNS=(
  "Block validation failed"
  "Behind! Should update to view"
  "Received nullification for past M-notarized view"
  "Cascading nullification from view"
  "Nullifying range from view"
  "Replaying "
  "Current view has a pending block, but the view has progressed with a m-notarization"
  "Ring buffer is full, retrying"
  "Notification channel full, dropped notification"
  "Error handling consensus message"
  "Error handling tick"
  "Deferred finalization failed"
  "Failed to process buffered message"
  "Failed to request block for view"
)

# Hard budget caps per pattern. Exceeding these signals instability/regression.
# These are intentionally conservative to avoid flaky failures while still surfacing issues.
declare -A PATTERN_BUDGETS=(
  ["Ring buffer is full, retrying"]=500
  ["Notification channel full, dropped notification"]=100
  ["Error handling consensus message"]=100
  ["Error handling tick"]=100
  ["Deferred finalization failed"]=100
  ["Failed to process buffered message"]=100
  ["Failed to request block for view"]=100
  ["Block validation failed"]=500
  ["Behind! Should update to view"]=500
  ["Received nullification for past M-notarized view"]=200
  ["Cascading nullification from view"]=200
  ["Nullifying range from view"]=200
  ["Replaying "]=1000
  ["Current view has a pending block, but the view has progressed with a m-notarization"]=200
)

# Tests that are expected to trigger fault-recovery paths.
FAULT_TESTS=(
  "test_e2e_consensus_with_crashed_replica"
  "test_e2e_consensus_with_equivocating_leader"
  "test_e2e_consensus_with_persistent_equivocating_leader"
  "test_e2e_consensus_with_invalid_block_from_leader"
  "test_e2e_consensus_with_true_equivocation"
)

STRICT_TESTS=(
  "test_e2e_consensus_happy_path"
  "test_e2e_consensus_continuous_load"
  "test_e2e_consensus_functional_blockchain"
  "test_e2e_consensus_invalid_tx_rejection"
)

test_in_array() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}
