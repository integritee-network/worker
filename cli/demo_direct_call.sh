#!/bin/bash

# Executes a direct call on a worker and checks the balance afterwards.
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
# then run this script

# usage:
#  demo_direct_call.sh -p <NODEPORT> -P <WORKERPORT> -t <TEST_BALANCE_RUN>
#
# TEST_BALANCE_RUN is either "first" or "second"


while getopts ":p:P:t:u:V:C:" opt; do
    case $opt in
        t)
            TEST=$OPTARG
            ;;
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

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

echo "Using client binary ${CLIENT_BIN}"
${CLIENT_BIN} --version
echo "Using node uri ${INTEGRITEE_RPC_URL}:${INTEGRITEE_RPC_PORT}"
echo "Using trusted-worker uri ${WORKER_1_URL}:${WORKER_1_PORT}"
echo ""


AMOUNTSHIELD=5000000000000
AMOUNTTRANSFER=4000000000000

CLIENT="${CLIENT_BIN} -p ${INTEGRITEE_RPC_PORT} -P ${WORKER_1_PORT} -u ${INTEGRITEE_RPC_URL} -U ${WORKER_1_URL}"
# we simply believe the enclave here without verifying the teerex RA
MRENCLAVE="$($CLIENT trusted get-fingerprint)"
echo "Using MRENCLAVE: ${MRENCLAVE}"

VAULT=$(${CLIENT} trusted get-shard-vault)
echo "  Vault account = ${VAULT}"

echo "* Create a new incognito account for Bob"
ICGACCOUNTBOB=//BobIncognito
echo "  Bob's incognito account = ${ICGACCOUNTBOB}"
echo ""

echo "* Shield ${AMOUNTSHIELD} tokens to Charlie's account on L2"
${CLIENT} transfer //Charlie ${VAULT} ${AMOUNTSHIELD}
echo ""

echo "* Waiting 30 seconds"
sleep 30
echo ""

echo "Get balance of Charlie's incognito account"
${CLIENT} trusted --mrenclave ${MRENCLAVE} balance //Charlie
echo ""

# Send funds from Charlie to Bob's account.
echo "* Send ${AMOUNTTRANSFER} funds from Charlie's incognito account to Bob's incognito account"
$CLIENT trusted --mrenclave ${MRENCLAVE} --direct transfer //Charlie ${ICGACCOUNTBOB} ${AMOUNTTRANSFER}
echo ""

# Prevent getter being executed too early and returning an outdated result, before the transfer was made.
echo "* Waiting 2 seconds"
sleep 2
echo ""

echo "* Get balance of Charlie's incognito account"
RESULT=$(${CLIENT} trusted --mrenclave ${MRENCLAVE} balance //Charlie | xargs)
echo $RESULT
echo ""

echo "* Bob's incognito account balance"
RESULT=$(${CLIENT} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTBOB} | xargs)
echo $RESULT
echo ""


# The following tests are for automated CI.
# They only work if you're running from fresh genesis.
case $TEST in
    first)
        if [ "4000000000000" = "$RESULT" ]; then
            echo "test passed (1st time)"
            echo ""
            exit 0
        else
            echo "test ran through but balance is wrong. have you run the script from fresh genesis?"
            exit 1
        fi
        ;;
    second)
        if [ "8000000000000" = "$RESULT" ]; then
            echo "test passed (2nd time)"
            echo ""
            exit 0
        else
            echo "test ran through but balance is wrong. is this really the second time you run this since genesis?"
            exit 1
        fi
        ;;
esac

exit 0
