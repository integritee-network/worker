#!/bin/bash
set -euo pipefail

cd "$CLIENT_DIR" || exit

if [[ -z "${LOG_1}" ]] && [[ -z "${LOG_2}" ]]; then
  # we are in github actions if this exists, then we print to the logs

    echo "We are in ga actions!"

    touch "$LOG_1"
    touch "$LOG_2"

  ./demo_direct_call.sh -p 9944 -P 2000 -t first  2>&1 | tee "$LOG_1"
  ./demo_direct_call.sh -p 9944 -P 2000 -t second  2>&1 | tee "$LOG_2"
else

  echo "NOT IN GA!"

  ./demo_direct_call.sh -p 9944 -P 2000 -t first
  ./demo_direct_call.sh -p 9944 -P 2000 -t second
fi