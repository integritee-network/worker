#!/bin/bash
set -euo pipefail

# Runs sidechain demo: Either set `CLIENT_DIR` env var directly or run script with:
#
# source ./init_env.sh && ./sidechain.sh

cd "$CLIENT_DIR" || exit

LOG="${LOG:-$LOG_DIR/sidechain_demo.log}"

echo "[sidechain.sh] printing to logs:"
echo "        $LOG"

touch "$LOG"

./demo_sidechain.sh -p 9944 -A 2000 -B 3000 -C ./../bin/integritee-cli 2>&1 | tee "$LOG"