#!/bin/bash
# Restore the deployments data directory from a backup archive.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
BACKUP_FILE="${1:?Usage: restore.sh <backup-file.tar.gz>}"

if [ ! -f "$BACKUP_FILE" ]; then
  echo "Error: backup file not found: ${BACKUP_FILE}"
  exit 1
fi

echo "Restoring ${BACKUP_FILE} to ${DATA_DIR} ..."
mkdir -p "$DATA_DIR"
tar -xzf "$BACKUP_FILE" -C "$DATA_DIR"
echo "Restore complete."
