#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REPORT=${1:-"$REPO_ROOT/packages/core/etc/core.api.md"}

if [ ! -f "$REPORT" ]; then
  echo "API report not found: $REPORT"
  exit 1
fi

LC_ALL=C sed 's/\r$//' "$REPORT" | sha256sum | awk '{print $1}'
