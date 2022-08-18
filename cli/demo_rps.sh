#!/bin/bash
set -euo pipefail

# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --tmp --dev -lruntime=debug
#   rm light_client_db.bin
#   integritee-service init_shard
#   integritee-service shielding-key
#   integritee-service signing-key
#   export RUST_LOG=integritee_service=info,ita_stf=debug
#   integritee-service run
#
# then run this script

# usage:
#  demo_rps.sh -p <NODEPORT> -P <WORKERPORT> -m file

while getopts ":m:p:P:u:V:C:" opt; do
    case $opt in
        m)
            READMRENCLAVE=$OPTARG
            ;;
        p)
            NPORT=$OPTARG
            ;;
        P)
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
    esac
done

# Using default port if none given as arguments.
NPORT=${NPORT:-9944}
NODEURL=${NODEURL:-"ws://127.0.0.1"}

WORKER1PORT=${WORKER1PORT:-2000}
WORKER1URL=${WORKER1URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

READMRENCLAVE=${READMRENCLAVE:-"onchain-registry"}

echo "Using client binary ${CLIENT_BIN}"
echo "Using node uri ${NODEURL}:${NPORT}"
echo "Using trusted-worker uri ${WORKER1URL}:${WORKER1PORT}"
echo "Reading MRENCLAVE from ${READMRENCLAVE}"

CLIENT="${CLIENT_BIN} -p ${NPORT} -P ${WORKER1PORT} -u ${NODEURL} -U ${WORKER1URL}"

if [ "$READMRENCLAVE" = "file" ]
then
    read MRENCLAVE <<< $(cat ~/mrenclave.b58)
    echo "Reading MRENCLAVE from file: ${MRENCLAVE}"
else
    # this will always take the first MRENCLAVE found in the registry !!
    read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
    echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"
fi
[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }

PLAYER1=$($CLIENT trusted --mrenclave "$MRENCLAVE" new-account)
PLAYER2=$($CLIENT trusted --mrenclave "$MRENCLAVE" new-account)

echo "Alice (sudo) sets initial balances"
${CLIENT} trusted --mrenclave "${MRENCLAVE}" --direct set-balance "${PLAYER1}" 1000
${CLIENT} trusted --mrenclave "${MRENCLAVE}" --direct set-balance "${PLAYER2}" 1000
echo ""

echo "Alice starts new game against Bob"
# shellcheck disable=SC2086
${CLIENT} trusted --mrenclave "${MRENCLAVE}" --direct new-game "${PLAYER1}" "${PLAYER2}"
echo ""

echo "Alice chooses her weapon"
${CLIENT} trusted --mrenclave "${MRENCLAVE}" --direct choose "${PLAYER1}" Rock
echo ""

echo "Bob chooses his weapon"
${CLIENT} trusted --mrenclave "${MRENCLAVE}" --direct choose "${PLAYER2}" Paper
echo ""

echo "Alice reveals"
${CLIENT} trusted --mrenclave "${MRENCLAVE}" --direct reveal "${PLAYER1}" Rock
echo ""

echo "Bob reveals"
${CLIENT} trusted --mrenclave "${MRENCLAVE}" --direct reveal "${PLAYER2}" Paper
echo ""

echo "Query result"
${CLIENT} trusted --mrenclave "${MRENCLAVE}" --direct get-game "${PLAYER1}"
echo ""

exit 0
