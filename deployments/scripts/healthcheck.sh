#!/bin/sh
# Health check for the kairos-node Docker container.
# Uses wget to probe the Prometheus metrics endpoint (always available).
# Returns 0 (healthy) if the endpoint responds, 1 (unhealthy) otherwise.

set -e
wget -q --spider http://localhost:9090/metrics
