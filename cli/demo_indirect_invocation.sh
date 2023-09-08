#!/bin/bash
set -euo pipefail

# Runs the direct call demo twice, with worker 1 and worker 2.
#
# It does the same as `./scripts/m6.sh`, but is mainly used in the docker tests.

while getopts ":p:A:B:u:W:V:C:" opt; do
    case $opt in
        p)
            INTEGRITEE_RPC_PORT=$OPTARG
            ;;
        A)
            WORKER_1_PORT=$OPTARG
            ;;
        B)
            WORKER_2_PORT=$OPTARG
            ;;
        u)
            INTEGRITEE_RPC_URL=$OPTARG
            ;;
        V)
            WORKER_1_URL=$OPTARG
            ;;
        W)
            WORKER_2_URL=$OPTARG
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
INTEGRITEE_RPC_PORT=${INTEGRITEE_RPC_PORT:-9944}
INTEGRITEE_RPC_URL=${INTEGRITEE_RPC_URL:-"ws://127.0.0.1"}

WORKER_1_PORT=${WORKER_1_PORT:-2000}
WORKER_1_URL=${WORKER_1_URL:-"wss://127.0.0.1"}

WORKER_2_PORT=${WORKER_2_PORT:-3000}
WORKER_2_URL=${WORKER_2_URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

echo "Using client binary ${CLIENT_BIN}"
${CLIENT_BIN} --version
echo "Using node uri ${INTEGRITEE_RPC_URL}:${INTEGRITEE_RPC_PORT}"
echo "Using trusted-worker 1 uri ${WORKER_1_URL}:${WORKER_1_PORT}"
echo "Using trusted-worker 2 uri ${WORKER_2_URL}:${WORKER_2_PORT}"
echo ""

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

"${SCRIPT_DIR}"/demo_shielding_unshielding.sh -p "${INTEGRITEE_RPC_PORT}" -u "${INTEGRITEE_RPC_URL}" -V "${WORKER_1_URL}" -P "${WORKER_1_PORT}" -C "${CLIENT_BIN}" -t first
"${SCRIPT_DIR}"/demo_shielding_unshielding.sh -p "${INTEGRITEE_RPC_PORT}" -u "${INTEGRITEE_RPC_URL}" -V "${WORKER_2_URL}" -P "${WORKER_2_PORT}" -C "${CLIENT_BIN}" -t second

exit 0
