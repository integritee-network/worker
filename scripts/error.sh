#!/bin/bash
set -euo pipefail

# Runs M6 demo: Either set `CLIENT_DIR` env var directly or run script with:
#
# source ./init_env.sh && ./m6.sh

echo "$CLIENT_DIR"

cd "$CLIENT_DIR" || exit

LOG_1="${LOG_1:-$LOG_DIR/demo_shielding_error.log}"

echo "[shielding_error.sh] printing to logs:"
echo "        $LOG_1"

touch "$LOG_1"

./demo_shielding_error.sh -p 9944 -P 2000 -t first 2>&1 | tee "$LOG_1"
