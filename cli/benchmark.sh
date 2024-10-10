#!/bin/bash

while getopts ":p:A:u:V:C:" opt; do
    case $opt in
        p)
            NPORT=$OPTARG
            ;;
        A)
            WORKER1PORT=$OPTARG
            ;;
        u)
            NODEURL=$OPTARG
            ;;
        V)
            WORKER1URL=$OPTARG
            ;;
        C)
            CLIENT_BIN=$OPTARG
            ;;
        *)
            ;;
    esac
done

# using default port if none given as arguments
NPORT=${NPORT:-9944}
NODEURL=${NODEURL:-"ws://127.0.0.1"}

WORKER1PORT=${WORKER1PORT:-2000}
WORKER1URL=${WORKER1URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

echo "Using client binary ${CLIENT_BIN}"
echo "Using node uri ${NODEURL}:${NPORT}"
echo "Using trusted-worker uri ${WORKER1URL}:${WORKER1PORT}"

CLIENTWORKER1="${CLIENT_BIN} -p ${NPORT} -P ${WORKER1PORT} -u ${NODEURL} -U ${WORKER1URL}"

# we simply believe the enclave here without verifying the teerex RA
MRENCLAVE="$($CLIENTWORKER1 trusted get-fingerprint)"
echo "Using MRENCLAVE: ${MRENCLAVE}"

# needed when many clients are started
ulimit -S -n 4096

echo "Starting benchmark"
${CLIENTWORKER1} trusted --direct --mrenclave "${MRENCLAVE}" benchmark 20 100 -w
echo ""

exit 0
