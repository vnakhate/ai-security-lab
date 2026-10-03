#!/usr/bin/env bash
# Run from any directory. Collection requires an explicit target and scope.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required. Install it, then rerun this launcher." >&2
  exit 2
fi
exec python3 -u "$SCRIPT_DIR/run_assessment.py" "$@"
