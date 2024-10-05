#!/bin/bash

# Sidechain Demo:
#
# Demonstrates that transfers happening on worker1 are communicated via sidechain blocks to worker2.
# It does essentially the same as `m8.sh`, but in one script and more streamlined.
#
# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --tmp --dev -lruntime=debug
#   rm light_client_db.bin
#   export RUST_LOG=integritee_service=info,ita_stf=debug
#   integritee-service init_shard
#   integritee-service shielding-key
#   integritee-service signing-key
#   integritee-service run
#
# Then run this script.
#
# usage:
#  export RUST_LOG_LOG=integritee-cli=info,ita_stf=info
#  demo_sidechain.sh -p <NODEPORT> -A <WORKER_1_PORT> -B <WORKER_2_PORT> -m file
#
# TEST_BALANCE_RUN is either "first" or "second"
# if -m file is set, the mrenclave will be read from file.

while getopts ":m:p:A:B:t:u:W:V:C:" opt; do
    case $opt in
        m)
            READ_MRENCLAVE=$OPTARG
            ;;
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

# the parentchain token is 12 decimal
UNIT=$(( 10 ** 12 ))
FEE_TOLERANCE=$((10 ** 11))

INITIALFUNDS=$((5 * UNIT))
AMOUNTTRANSFER=$((2 * UNIT))

CLIENTWORKER1="${CLIENT_BIN} -p ${INTEGRITEE_RPC_PORT} -P ${WORKER_1_PORT} -u ${INTEGRITEE_RPC_URL} -U ${WORKER_1_URL}"
CLIENTWORKER2="${CLIENT_BIN} -p ${INTEGRITEE_RPC_PORT} -P ${WORKER_2_PORT} -u ${INTEGRITEE_RPC_URL} -U ${WORKER_2_URL}"

if [ "$READ_MRENCLAVE" = "file" ]
then
    read MRENCLAVE <<< $(cat ~/mrenclave.b58)
    echo "Reading MRENCLAVE from file: ${MRENCLAVE}"
else
    # This will always take the first MRENCLAVE found in the registry !!
    read MRENCLAVE <<< $($CLIENTWORKER1 list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
    echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"
fi
[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }

VAULT=$(${CLIENT} trusted get-shard-vault)
echo "  Vault account = ${VAULT}"

echo "* Create a new incognito account for Bob"
ICGACCOUNTBOB=//BobIncognito
echo "  Bob's incognito account = ${ICGACCOUNTBOB}"
echo ""

echo "* Shield ${INITIALFUNDS} tokens to Charlie's account on L2"
${CLIENT} transfer //Charlie ${VAULT} ${INITIALFUNDS}
echo ""

echo "* Waiting 30 seconds"
sleep 30
echo ""

echo "Get balance of Charlie's incognito account (on worker 1)"
${CLIENTWORKER1} trusted --mrenclave ${MRENCLAVE} balance //Charlie
echo ""

# Send funds from Charlie to Bobs account, on worker 1.
echo "* First transfer: Send ${AMOUNTTRANSFER} funds from Charlie's incognito account to Bob's incognito account (on worker 1)"
$CLIENTWORKER1 trusted --mrenclave ${MRENCLAVE} --direct transfer //Charlie ${ICGACCOUNTBOB} ${AMOUNTTRANSFER}
echo ""

# Prevent nonce clash when sending direct trusted calls to different workers.
echo "* Waiting 2 seconds"
sleep 2
echo ""

# Send funds from Charlie to Bobs account, on worker 2.
echo "* Second transfer: Send ${AMOUNTTRANSFER} funds from Charlie's incognito account to Bob's incognito account (on worker 2)"
$CLIENTWORKER2 trusted --mrenclave ${MRENCLAVE} --direct transfer //Charlie ${ICGACCOUNTBOB} ${AMOUNTTRANSFER}
echo ""

# Prevent getter being executed too early and returning an outdated result, before the transfer was made.
echo "* Waiting 2 seconds"
sleep 2
echo ""

echo "* Get balance of Charlie's incognito account (on worker 1)"
CHARLIE_BALANCE=$(${CLIENTWORKER1} trusted --mrenclave ${MRENCLAVE} balance //Charlie | xargs)
echo "$CHARLIE_BALANCE"
echo ""

echo "* Get balance of Bob's incognito account (on worker 2)"
BOB_BALANCE=$(${CLIENTWORKER2} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTBOB} | xargs)
echo "$BOB_BALANCE"
echo ""

CHARLIE_EXPECTED_BALANCE=$(( 1 * UNIT ))
BOB_EXPECTED_BALANCE=$(( 4 * UNIT ))

echo "* Verifying Charlie's balance"
if (( CHARLIE_BALANCE >= CHARLIE_EXPECTED_BALANCE ? CHARLIE_BALANCE - CHARLIE_EXPECTED_BALANCE > FEE_TOLERANCE : CHARLIE_EXPECTED_BALANCE - CHARLIE_BALANCE > FEE_TOLERANCE)); then
  echo "Charlie's balance is wrong (expected: $CHARLIE_EXPECTED_BALANCE, actual: $CHARLIE_BALANCE), tolerance = $FEE_TOLERANCE"
  exit 1
else
    echo "Charlie's balance is correct ($CHARLIE_BALANCE)"
fi
echo ""

echo "* Verifying Bob's balance"
if [ "$BOB_BALANCE" -ne "$BOB_EXPECTED_BALANCE" ]; then
  echo "Bob's balance is wrong (expected: $BOB_EXPECTED_BALANCE, actual: $BOB_BALANCE)"
  exit 1
else
    echo "Bob's balance is correct ($BOB_BALANCE)"
fi
echo ""

exit 0
