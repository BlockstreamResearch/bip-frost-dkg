#!/bin/sh
set -e

# Check that mypy is available
command -v mypy >/dev/null 2>&1 || { echo >&2 "mypy is required but it's not installed.  Aborting."; exit 1; }

cd "$(dirname "$0")"
mypy --no-error-summary .
python3 tests.py
