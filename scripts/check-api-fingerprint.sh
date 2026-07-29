#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
EXPECTED=$(cat "$REPO_ROOT/packages/core/API_FINGERPRINT")
CURRENT=$("$REPO_ROOT/scripts/api-fingerprint.sh")

if [ "$EXPECTED" != "$CURRENT" ]; then
  echo "Supplemental API report fingerprint mismatch"
  echo "Expected: $EXPECTED"
  echo "Current : $CURRENT"
  echo "Run 'pnpm -C packages/core api:report' to update the reviewed API report,"
  echo "then update packages/core/API_FINGERPRINT with 'pnpm -C packages/core api:fingerprint'."
  exit 1
fi

echo "Supplemental API report fingerprint OK"
