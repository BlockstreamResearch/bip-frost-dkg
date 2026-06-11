#!/bin/sh
set -e

command -v coverage > /dev/null 2>&1 || {
  echo >&2 "coverage is required but it's not installed. Aborting."
  exit 1
}

cd "$(dirname "$0")"

coverage run --branch --source=chilldkg_ref tests.py
coverage report -m
coverage html
