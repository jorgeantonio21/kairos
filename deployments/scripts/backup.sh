#!/bin/bash
# Backup the deployments data directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
BACKUP_DIR="${1:-.}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/kairos-backup-${TIMESTAMP}.tar.gz"

if [ ! -d "$DATA_DIR" ]; then
  echo "Error: data directory not found at ${DATA_DIR}"
  exit 1
fi

echo "Backing up ${DATA_DIR} ..."
tar -czf "$BACKUP_FILE" -C "$DATA_DIR" .
echo "Backup created: ${BACKUP_FILE} ($(du -h "$BACKUP_FILE" | cut -f1))"
