#!/usr/bin/env bash
# Local evidence collector. Run only against explicitly approved targets.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/waf_check.py" "$@"
