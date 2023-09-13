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
#  demo_direct_call.sh -p <NODEPORT> -P <WORKERPORT> -t <TEST_BALANCE_RUN> -m file
#
# TEST_BALANCE_RUN is either "first" or "second"
# if -m file is set, the mrenclave will be read from file

while getopts ":m:p:P:t:u:V:C:" opt; do
    case $opt in
        t)
            TEST=$OPTARG
            ;;
        m)
            READ_MRENCLAVE=$OPTARG
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


AMOUNTSHIELD=50000000000
AMOUNTTRANSFER=40000000000

CLIENT="${CLIENT_BIN} -p ${INTEGRITEE_RPC_PORT} -P ${WORKER_1_PORT} -u ${INTEGRITEE_RPC_URL} -U ${WORKER_1_URL}"
read -r MRENCLAVE <<< "$($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')"

echo ""
echo "* Create a new incognito account for Alice"
ICGACCOUNTALICE=//AliceIncognito
echo "  Alice's incognito account = ${ICGACCOUNTALICE}"
echo ""

echo "* Create a new incognito account for Bob"
ICGACCOUNTBOB=//BobIncognito
echo "  Bob's incognito account = ${ICGACCOUNTBOB}"
echo ""

echo "* Issue ${AMOUNTSHIELD} tokens to Alice's incognito account"
${CLIENT} trusted --mrenclave ${MRENCLAVE} --direct set-balance ${ICGACCOUNTALICE} ${AMOUNTSHIELD}
echo ""

echo "Get balance of Alice's incognito account"
${CLIENT} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTALICE}
echo ""

# Send funds from Alice to Bob's account.
echo "* Send ${AMOUNTTRANSFER} funds from Alice's incognito account to Bob's incognito account"
$CLIENT trusted --mrenclave ${MRENCLAVE} --direct transfer ${ICGACCOUNTALICE} ${ICGACCOUNTBOB} ${AMOUNTTRANSFER}
echo ""

# Prevent getter being executed too early and returning an outdated result, before the transfer was made.
echo "* Waiting 2 seconds"
sleep 2
echo ""

echo "* Get balance of Alice's incognito account"
RESULT=$(${CLIENT} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTALICE} | xargs)
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
        if [ "40000000000" = "$RESULT" ]; then
            echo "test passed (1st time)"
            echo ""
            exit 0
        else
            echo "test ran through but balance is wrong. have you run the script from fresh genesis?"
            exit 1
        fi
        ;;
    second)
        if [ "80000000000" = "$RESULT" ]; then
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
