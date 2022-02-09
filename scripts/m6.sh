#!/bin/bash
set -euo pipefail

# Runs M6 demo: Either set `CLIENT_DIR` env var directly or run script with:
#
# source ./init_env.sh && ./m6.sh

echo "$CLIENT_DIR"

cd "$CLIENT_DIR" || exit

LOG_1="${LOG_1:-$LOG_DIR/m6_demo_shielding_unshielding_1.log}"
LOG_2="${LOG_2:-$LOG_DIR/m6_demo_shielding_unshielding_2.log}"

echo "[m6.sh] printing to logs:"
echo "        $LOG_1"
echo "        $LOG_2"

touch "$LOG_1"
touch "$LOG_2"

./demo_shielding_unshielding.sh -p 9944 -P 2000 -t first 2>&1 | tee "$LOG_1"
./demo_shielding_unshielding.sh -p 9944 -P 3000 -t second 2>&1 | tee "$LOG_2"
