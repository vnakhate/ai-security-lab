#!/bin/sh
set -eu
LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "${1:-}" = "waf" ]; then
  shift
  exec "$LAB_DIR/waf-assessment/run-waf-assessment.sh" "$@"
fi
if [ -x "$LAB_DIR/.venv/bin/python" ]; then
  exec "$LAB_DIR/.venv/bin/python" "$LAB_DIR/harness.py" "$@"
fi
exec python3 "$LAB_DIR/harness.py" "$@"
