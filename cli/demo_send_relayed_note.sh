#!/bin/bash

# Sends a relayed note with a direct call to the worker which is expected
# to relay it via IPFS in encrypted form
#


# usage:
#  demo-send-relayed-note.sh -p <NODEPORT> -P <WORKERPORT> -i <IPFS_GATEWAY>
#
# TEST_BALANCE_RUN is either "first" or "second"


while getopts ":p:P:t:u:V:C:i:" opt; do
    case $opt in
        p)
            INTEGRITEE_RPC_PORT=$OPTARG
            ;;
        P)
            WORKER_1_PORT=$OPTARG
            ;;
        u)
            INTEGRITEE_RPC_URL=$OPTARG
            ;;
        V)
            WORKER_1_URL=$OPTARG
            ;;
        i)
            IPFS_GATEWAY=$OPTARG
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
IPFS_GATEWAY=${IPFS_GATEWAY:-"http://127.0.0.1:8080"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

echo "Using client binary ${CLIENT_BIN}"
${CLIENT_BIN} --version
echo "Using node uri ${INTEGRITEE_RPC_URL}:${INTEGRITEE_RPC_PORT}"
echo "Using trusted-worker uri ${WORKER_1_URL}:${WORKER_1_PORT}"
echo "Using IPFS gateway ${IPFS_GATEWAY}"
echo ""

CLIENT="${CLIENT_BIN} -p ${INTEGRITEE_RPC_PORT} -P ${WORKER_1_PORT} -u ${INTEGRITEE_RPC_URL} -U ${WORKER_1_URL} -i ${IPFS_GATEWAY}"
# we simply believe the enclave here without verifying the teerex RA
MRENCLAVE="$($CLIENT trusted get-fingerprint)"
echo "Using MRENCLAVE: ${MRENCLAVE}"
TCLIENT="${CLIENT} trusted  --mrenclave ${MRENCLAVE} --direct"

NOTE="Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
${TCLIENT} send-note --ipfs-proxy //Alice //Bob "${NOTE}"
echo "Alice sent note to Bob:"
echo $NOTE

RECEIVED_NOTE=$(${TCLIENT} get-notes //Bob 0 | grep "${NOTE}")

echo "Bob received:"
echo $RECEIVED_NOTE

if echo "$RECEIVED_NOTE" | grep -qF "$NOTE"; then
    echo "NOTE found in RECEIVED_NOTE"
    exit 0
else
    echo "NOTE not found in RECEIVED_NOTE"
    exit 1
fi
