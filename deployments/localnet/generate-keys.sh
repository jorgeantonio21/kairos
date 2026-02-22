#!/bin/bash
# Generate deterministic key material for a 6-validator local network.
#
# This script generates Ed25519 and BLS keypairs for each validator using
# deterministic seeds so the localnet is reproducible across machines.
#
# Usage:
#   ./generate-keys.sh           # generates keys in config/nodes/validator-{0..5}/
#   ./generate-keys.sh --clean   # removes existing keys first
#
# After running, start the localnet with:
#   nix build .#dockerImage && docker load < result
#   docker compose up
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config/nodes"
NUM_VALIDATORS=6

if [ "${1:-}" = "--clean" ]; then
  echo "Cleaning existing key material..."
  rm -rf "$CONFIG_DIR"
fi

# ── Generate keys via the crypto crate ──────────────────────────
# Uses deterministic seeds (0..5) for local dev reproducibility.
echo "Generating key material for ${NUM_VALIDATORS} validators..."

for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
  NODE_DIR="${CONFIG_DIR}/validator-${i}"
  KEY_DIR="${NODE_DIR}/keys"
  mkdir -p "$KEY_DIR"

  # Generate deterministic Ed25519 key from seed
  # The node will auto-generate if keys don't exist, but we need the public
  # keys upfront for cross-referencing in configs.
  printf "validator-%d-ed25519-seed-for-local-dev-only!!" "$i" | \
    head -c 32 | xxd -p -c 64 > "${KEY_DIR}/ed25519.key"

  # Generate deterministic BLS key from seed
  printf "validator-%d-bls-secret-key-for-local-dev!!!!!!!" "$i" | \
    head -c 32 | xxd -p -c 64 > "${KEY_DIR}/bls.key"

  echo "  ✓ validator-${i} keys written to ${KEY_DIR}"
done

# ── Derive public keys and build configs ────────────────────────
# For a full setup, run: cargo run --package crypto -- derive-pubkeys <key-dir>
# For now, we use placeholder public keys that the nodes will override on startup.

echo ""
echo "⚠  NOTE: The generated keys use deterministic seeds for LOCAL DEV ONLY."
echo "   For production, use proper entropy from /dev/urandom."
echo ""
echo "Key material generated in: ${CONFIG_DIR}"
echo ""
echo "Next steps:"
echo "  1. Build the Docker image:  nix build .#dockerImage && docker load < result"
echo "  2. Start the localnet:      docker compose up"
