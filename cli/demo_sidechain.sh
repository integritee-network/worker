#!/bin/bash

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
#  export RUST_LOG_LOG=integritee-cli=info,ita_stf=info
#  demo_sidechain.sh -p <NODEPORT> -A <WORKER1PORT> -B <WORKER2PORT> -m file
#
# TEST_BALANCE_RUN is either "first" or "second"
# if -m file is set, the mrenclave will be read from file

while getopts ":m:p:A:B:t:" opt; do
    case $opt in
        t)
            TEST=$OPTARG
            ;;
        m)
            READMRENCLAVE=$OPTARG
            ;;
        p)
            NPORT=$OPTARG
            ;;
        A)
            WORKER1PORT=$OPTARG
            ;;
        B)
            WORKER2PORT=$OPTARG
            ;;
    esac
done

# using default port if none given as arguments
NPORT=${NPORT:-9944}
WORKER1PORT=${WORKER1PORT:-2000}
WORKER2PORT=${WORKER2PORT:-3000}

echo "Using node-port ${NPORT}"
echo "Using trusted-worker-1-port ${WORKER1PORT}"
echo "Using trusted-worker-2-port ${WORKER2PORT}"

INITIALFUNDS=50000000000
AMOUNTTRANSFER=20000000000

CLIENTWORKER1="./../bin/integritee-cli -p ${NPORT} -P ${WORKER1PORT}"
CLIENTWORKER2="./../bin/integritee-cli -p ${NPORT} -P ${WORKER2PORT}"

if [ "$READMRENCLAVE" = "file" ]
then
    read MRENCLAVE <<< $(cat ~/mrenclave.b58)
    echo "Reading MRENCLAVE from file: ${MRENCLAVE}"
else
    # this will always take the first MRENCLAVE found in the registry !!
    read MRENCLAVE <<< $($CLIENTWORKER1 list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
    echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"
fi
[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }

echo ""
echo "* Create a new incognito account for Alice"
ICGACCOUNTALICE=//AliceIncognito
echo "  Alice's incognito account = ${ICGACCOUNTALICE}"
echo ""

echo "* Create a new incognito account for Bob"
ICGACCOUNTBOB=//BobIncognito
echo "  Bob's incognito account = ${ICGACCOUNTBOB}"
echo ""

echo "* Issue ${INITIALFUNDS} tokens to Alice's incognito account (on worker 1)"
${CLIENTWORKER1} trusted --mrenclave ${MRENCLAVE} --direct set-balance ${ICGACCOUNTALICE} ${INITIALFUNDS}
echo ""

echo "Get balance of Alice's incognito account (on worker 1)"
${CLIENTWORKER1} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTALICE}
echo ""

# Send funds from Alice to Bobs account, on worker 1
echo "* First transfer: Send ${AMOUNTTRANSFER} funds from Alice's incognito account to Bob's incognito account (on worker 1)"
$CLIENTWORKER1 trusted --mrenclave ${MRENCLAVE} --direct transfer ${ICGACCOUNTALICE} ${ICGACCOUNTBOB} ${AMOUNTTRANSFER}
echo ""

# Send funds from Alice to Bobs account, on worker 2
echo "* Second transfer: Send ${AMOUNTTRANSFER} funds from Alice's incognito account to Bob's incognito account (on worker 2)"
$CLIENTWORKER2 trusted --mrenclave ${MRENCLAVE} --direct transfer ${ICGACCOUNTALICE} ${ICGACCOUNTBOB} ${AMOUNTTRANSFER}
echo ""

echo "* Get balance of Alice's incognito account (on worker 2)"
ALICE_BALANCE=$(${CLIENTWORKER2} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTALICE} | xargs)
echo "$ALICE_BALANCE"
echo ""

echo "* Get balance of Bob's incognito account (on worker 2)"
BOB_BALANCE=$(${CLIENTWORKER2} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTBOB} | xargs)
echo "$BOB_BALANCE"
echo ""

ALICE_EXPECTED_BALANCE=10000000000
BOB_EXPECTED_BALANCE=40000000000

echo "* Verifying Alice's balance"
if [ "$ALICE_BALANCE" -ne "$ALICE_EXPECTED_BALANCE" ]; then
  echo "Alice's balance is wrong (expected: $ALICE_EXPECTED_BALANCE, actual: $ALICE_BALANCE)"
  exit 1
else
    echo "Alice's balance is correct ($ALICE_BALANCE)"
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
