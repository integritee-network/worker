#!/bin/bash
set -euo pipefail

# Runs Teeracle1 demo: Either set `CLIENT_DIR` env var directly or run script with:
#
# source ./init_env.sh && ./teeracle.sh

echo "$CLIENT_DIR"

cd "$CLIENT_DIR" || exit

LOG_1="${LOG_1:-$LOG_DIR/teeracle1_demo_whitelist.log}"

echo "[teeracle.sh] printing to logs:"
echo "        $LOG_1"

touch "$LOG_1"

./demo_teeracle_whitelist.sh -p 9944 -P 2000 -d 120 -i 24 2>&1 | tee "$LOG_1"
