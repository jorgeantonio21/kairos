#!/bin/bash
# Generate deterministic key material and compose-ready configs for a 6-validator local network.
#
# This script generates Ed25519 and BLS keypairs for each validator using
# deterministic seeds so the localnet is reproducible across machines.
#
# Usage:
#   ./generate-keys.sh           # generates keys + node.toml files in config/nodes/validator-{0..5}/
#   ./generate-keys.sh --clean   # removes existing generated config first
#
# After running, start the localnet with:
#   nix build .#dockerImage && docker load < result
#   docker compose up
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config/nodes"
SHARED_THRESHOLD_DIR="${SCRIPT_DIR}/shared/threshold"
NUM_VALIDATORS=6
VALIDATOR_SET_ID="kairos-local-vs-1"

if [ "${1:-}" = "--clean" ]; then
	echo "Cleaning existing key material..."
	rm -rf "$CONFIG_DIR"
	rm -rf "$SHARED_THRESHOLD_DIR"
fi

# ── Generate key files (local dev only) ─────────────────────────
echo "Generating key material for ${NUM_VALIDATORS} validators..."

for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
	NODE_DIR="${CONFIG_DIR}/validator-${i}"
	KEY_DIR="${NODE_DIR}/keys"
	mkdir -p "$KEY_DIR"

	# Generate deterministic Ed25519 key from seed
	# The node will auto-generate if keys don't exist, but we need the public
	# keys upfront for cross-referencing in configs.
	printf "validator-%d-ed25519-seed-for-local-dev-only!!" "$i" |
		head -c 32 | xxd -p -c 64 >"${KEY_DIR}/ed25519.key"

	# Generate deterministic BLS key from seed
	printf "validator-%d-bls-secret-key-for-local-dev!!!!!!!" "$i" |
		head -c 32 | xxd -p -c 64 >"${KEY_DIR}/bls.key"

	echo "  ✓ validator-${i} keys written to ${KEY_DIR}"
done

echo ""
echo "Generating validator config files..."
TMP_CONFIG_DIR="$(mktemp -d)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Generate canonical node configs from the current binary logic.
cargo run -p node -- generate-configs --output-dir "${TMP_CONFIG_DIR}" >/dev/null

for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
	NODE_DIR="${CONFIG_DIR}/validator-${i}"
	NODE_TOML="${NODE_DIR}/node.toml"

	cp "${TMP_CONFIG_DIR}/node${i}.toml" "${NODE_TOML}"

	# Docker-localnet addresses:
	# - fixed container IPs (172.30.0.10..15) for SocketAddr parsing
	# - container-internal listen ports
	awk -v ip="$((10 + i))" '
BEGIN{in_p2p=0;in_rpc=0}
/^\[p2p\]/{in_p2p=1;in_rpc=0;print;next}
/^\[rpc\]/{in_p2p=0;in_rpc=1;print;next}
/^\[/{in_p2p=0;in_rpc=0;print;next}
{
  if(in_p2p && $0 ~ /^listen_addr[[:space:]]*=/){print "listen_addr                 = \"0.0.0.0:9000\""; next}
  if(in_p2p && $0 ~ /^external_addr[[:space:]]*=/){print "external_addr               = \"172.30.0." ip ":9000\""; next}
  if(in_rpc && $0 ~ /^listen_addr[[:space:]]*=/){print "listen_addr            = \"0.0.0.0:50051\""; next}
  print
}' "${NODE_TOML}" >"${NODE_TOML}.tmp" && mv "${NODE_TOML}.tmp" "${NODE_TOML}"

	sed -i.bak \
		-e 's|127\.0\.0\.1:9000|172.30.0.10:9000|g' \
		-e 's|127\.0\.0\.1:9100|172.30.0.11:9000|g' \
		-e 's|127\.0\.0\.1:9200|172.30.0.12:9000|g' \
		-e 's|127\.0\.0\.1:9300|172.30.0.13:9000|g' \
		-e 's|127\.0\.0\.1:9400|172.30.0.14:9000|g' \
		-e 's|127\.0\.0\.1:9500|172.30.0.15:9000|g' \
		"${NODE_TOML}"
	rm -f "${NODE_TOML}.bak"

	# Fill identity table in-place (generator creates an empty [identity] block).
	# Recreate metrics/logging blocks exactly once to keep this script idempotent.
	awk '
BEGIN{
  in_identity=0
  skip_metrics=0
  skip_logging=0
  saw_metrics=0
  saw_logging=0
}
/^\[identity\]$/{
  print
  print "bls_secret_key_path = \"/etc/kairos/keys/bls.key\""
  print "ed25519_secret_key_path = \"/etc/kairos/keys/ed25519.key\""
  in_identity=1
  next
}
/^\[metrics\]$/{
  saw_metrics=1
  skip_metrics=1
  next
}
/^\[logging\]$/{
  saw_logging=1
  skip_logging=1
  next
}
/^\[/{
  in_identity=0
  skip_metrics=0
  skip_logging=0
  print
  next
}
{
  if(in_identity || skip_metrics || skip_logging){next}
  print
}
END{
  if(!saw_metrics){
    print ""
  }
  print "[metrics]"
  print "enabled = true"
  print "listen_address = \"0.0.0.0:9090\""
  print ""
  print "[logging]"
  print "format = \"json\""
  print "level = \"info\""
}
' "${NODE_TOML}" >"${NODE_TOML}.tmp" && mv "${NODE_TOML}.tmp" "${NODE_TOML}"

	echo "  ✓ validator-${i} config written to ${NODE_TOML}"
done

rm -rf "${TMP_CONFIG_DIR}"

echo ""
echo "Preparing shared threshold artifact directory..."
mkdir -p "${SHARED_THRESHOLD_DIR}"
echo "  ✓ shared threshold artifact path: ${SHARED_THRESHOLD_DIR}"

echo ""
echo "Injecting threshold setup config..."
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
	NODE_DIR="${CONFIG_DIR}/validator-${i}"
	NODE_TOML="${NODE_DIR}/node.toml"
	FINALIZE_IF_LAST="false"
	if [ "$i" -eq $((NUM_VALIDATORS - 1)) ]; then
		FINALIZE_IF_LAST="true"
	fi

	awk \
		-v participant_index="$((i + 1))" \
		-v finalize_if_last="${FINALIZE_IF_LAST}" \
		-v validator_set_id="${VALIDATOR_SET_ID}" \
		-v artifact_path="/var/lib/kairos/threshold/validator-${i}.threshold_setup.json" \
		'
BEGIN{
  skip_threshold=0
}
/^\[threshold_setup\]$/{
  skip_threshold=1
  next
}
/^\[/{
  skip_threshold=0
  print
  next
}
{
  if(skip_threshold){next}
  print
}
END{
  print ""
  print "[threshold_setup]"
  print "mode = \"enabled\""
  print "artifact_path = \"" artifact_path "\""
  print "validator_set_id = \"" validator_set_id "\""
  print ""
  print "[threshold_setup.bootstrap]"
  print "endpoint = \"http://bootstrap-rpc:7001\""
  print "participant_index = " participant_index
  print "finalize_if_last = " finalize_if_last
  print "max_attempts = 60"
  print "backoff_ms = 1000"
}
' "${NODE_TOML}" >"${NODE_TOML}.tmp" && mv "${NODE_TOML}.tmp" "${NODE_TOML}"
	echo "  ✓ validator-${i} threshold setup configured"
done

echo ""
echo "Threshold bootstrap mode configured:"
echo "  - First run: validators generate artifacts via bootstrap-rpc"
echo "  - Subsequent runs: validators reuse ${SHARED_THRESHOLD_DIR}/validator-*.threshold_setup.json"
echo ""
echo "⚠  NOTE: The generated keys use deterministic seeds for LOCAL DEV ONLY."
echo "   For production, use proper entropy from /dev/urandom."
echo ""
echo "Key material and configs generated in: ${CONFIG_DIR}"
echo ""
echo "Next steps:"
echo "  1. Build the Docker image:  docker build -f ${REPO_ROOT}/deployments/Dockerfile -t kairos-node:latest ${REPO_ROOT}"
echo "  2. Start the localnet:      docker compose -f docker-compose.yml -f localnet.override.yml up -d"
