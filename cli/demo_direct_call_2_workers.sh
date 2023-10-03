#!/bin/bash
set -euo pipefail

# Runs the `demo_direct_call.sh` twice once with worker1 and worker2.
# This verifies that the two workers are successfully sharing state updates
# by broadcasting sidechain blocks.
#
# It does the same as `scripts/m8.sh`, but is mainly used in the docker tests.

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
        *)
            echo "invalid arg ${OPTARG}"
            exit 1
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

echo "Using client binary ${CLIENT_BIN}"
${CLIENT_BIN} --version
echo "Using node uri ${NODEURL}:${NPORT}"
echo "Using trusted-worker uri 1 ${WORKER1URL}:${WORKER1PORT}"
echo "Using trusted-worker uri 2 ${WORKER2URL}:${WORKER2PORT}"
echo ""

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

"${SCRIPT_DIR}"/demo_direct_call.sh -p "${NPORT}" -u "${NODEURL}" -V "${WORKER1URL}" -P "${WORKER1PORT}" -C "${CLIENT_BIN}" -t first
"${SCRIPT_DIR}"/demo_direct_call.sh -p "${NPORT}" -u "${NODEURL}" -V "${WORKER2URL}" -P "${WORKER2PORT}" -C "${CLIENT_BIN}" -t second

exit 0
