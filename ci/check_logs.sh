#!/bin/bash

# Fail fast if any commands exists with error
set -e

# Print all executed commands
set -x

for entry in `ls clippy_*.log`; do
    if grep -q error $entry; then
        echo "error(s) found"
        exit 1
    fi
    if grep -q warning $entry; then
        echo "warning(s) found"
        exit 1
    fi
done

exit 0
