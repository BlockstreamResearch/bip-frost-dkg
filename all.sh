#!/bin/sh

./update-pydoc.sh

cd python || exit 1
./tests.sh
./example.py
