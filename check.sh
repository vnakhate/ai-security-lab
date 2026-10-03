#!/usr/bin/env sh
set -eu
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON="$PROJECT_DIR/lab/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then PYTHON=python3; fi
export PYTHONDONTWRITEBYTECODE=1
"$PYTHON" -m unittest discover -s "$PROJECT_DIR/lab/tests" -v
"$PYTHON" -m unittest discover -s "$PROJECT_DIR/lab/waf-assessment/tests" -v
bash -n "$PROJECT_DIR/lab/waf-assessment/akamai-waf-check.sh"
bash -n "$PROJECT_DIR/lab/waf-assessment/run-waf-assessment.sh"
