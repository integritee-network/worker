#!/bin/bash
set -euo pipefail

# Runs the direct call demo twice, with worker 1 and worker 2.
#
# It does the same as `./scripts/m6.sh`, but is mainly used in the docker tests.

while getopts ":p:A:B:u:W:V:C:" opt; do
    case $opt in
        p)
            NPORT=$OPTARG
            ;;
        A)
            WORKER1PORT=$OPTARG
            ;;
        B)
            WORKER2PORT=$OPTARG
            ;;
        u)
            NODEURL=$OPTARG
            ;;
        V)
            WORKER1URL=$OPTARG
            ;;
        W)
            WORKER2URL=$OPTARG
            ;;
        C)
            CLIENT_BIN=$OPTARG
            ;;
    esac
done

# Using default port if none given as arguments.
NPORT=${NPORT:-9944}
NODEURL=${NODEURL:-"ws://127.0.0.1"}

WORKER1PORT=${WORKER1PORT:-2000}
WORKER1URL=${WORKER1URL:-"wss://127.0.0.1"}

WORKER2PORT=${WORKER2PORT:-3000}
WORKER2URL=${WORKER2URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

"${SCRIPT_DIR}"/demo_shielding_unshielding.sh -p "${NPORT}" -u "${NODEURL}" -V "${WORKER1URL}" -P "${WORKER1PORT}" -C "${CLIENT_BIN}" -t first
"${SCRIPT_DIR}"/demo_shielding_unshielding.sh -p "${NPORT}" -u "${NODEURL}" -V "${WORKER2URL}" -P "${WORKER2PORT}" -C "${CLIENT_BIN}" -t second

exit 0