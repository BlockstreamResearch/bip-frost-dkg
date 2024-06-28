#!/bin/sh
set -e

# Check that mypy is available
check_availability() {
  command -v "$1" > /dev/null 2>&1 || {
    echo >&2 "$1 is required but it's not installed. Aborting.";
    exit 1;
  }
}

check_availability mypy
check_availability ruff

cd "$(dirname "$0")"

# Keep going if a linter fails
ruff check --quiet || true
ruff format --diff --quiet || true
mypy --no-error-summary . || true

python3 tests.py
