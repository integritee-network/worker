#!/bin/bash
set -euo pipefail

# Runs M6 demo: Either set `CLIENT_DIR` env var directly or run script with:
#
# source ./init_env.sh && ./m8.sh

cd "$CLIENT_DIR" || exit

if [[ -z "$LOG_1" ]] && [[ -z "$LOG_2" ]]; then
  ./demo_shielding_unshielding.sh -p 9944 -P 2000 -t first
  ./demo_shielding_unshielding.sh -p 9944 -P 3000 -t second
else
  # we are in github actions if this exists, then we print to the logs

  echo "[m6.sh] printing to logs:"
  echo "        $LOG_1"
  echo "        $LOG_2"

  touch "$LOG_1"
  touch "$LOG_2"

  ./demo_shielding_unshielding.sh -p 9944 -P 2000 -t first 2>&1 | tee "$LOG_1"
  ./demo_shielding_unshielding.sh -p 9944 -P 3000 -t second 2>&1 | tee "$LOG_2"
fi
