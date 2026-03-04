#!/usr/bin/env bash

# Baseline metrics for scenario=localnet_steady_state.
# Values should be calibrated on a stable localnet perf runner.
# View baseline seeded from existing localnet A/B benchmark data in benchmarks/consensus-ab.

BASELINE_STEADY_STATE_VIEWS_PER_SEC=15.00
BASELINE_STEADY_STATE_FINALIZED_TPS=6.00
BASELINE_STEADY_STATE_INCLUSION_RATE=0.90
BASELINE_STEADY_STATE_LATENCY_P95_MS=3000
BASELINE_STEADY_STATE_LATENCY_P99_MS=5000
