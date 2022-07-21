#!/bin/bash
set -euo pipefail

# Runs M8 demo: Either set `CLIENT_DIR` env var directly or run script with:
#
# source ./init_env.sh && ./m8.sh

cd "$CLIENT_DIR" || exit

LOG_1="${LOG_1:-$LOG_DIR/m8_demo_direct_call_1.log}"
LOG_2="${LOG_2:-$LOG_DIR/m8_demo_direct_call_2.log}"

echo "[m8.sh] printing to logs:"
echo "        $LOG_1"
echo "        $LOG_2"

touch "$LOG_1"
touch "$LOG_2"

./demo_direct_call.sh -p 9944 -P 2000 -C ./../bin/integritee-cli -t first 2>&1 | tee "$LOG_1"
./demo_direct_call.sh -p 9944 -P 3000 -C ./../bin/integritee-cli -t second 2>&1 | tee "$LOG_2"
