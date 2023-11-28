#!/bin/bash

# to make sure the script aborts when (sub-)function exits abnormally
set -e

# Demonstrates how to shield tokens from the parentchain into the sidechain.
#
# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --dev -lruntime=debug
#   rm light_client_db.bin
#   export RUST_LOG=integritee_service=info,ita_stf=debug
#   integritee-service init_shard
#   integritee-service shielding-key
#   integritee-service signing-key
#   integritee-service run
#
# then run this script

# usage:
#  demo_shielding_unshielding.sh -p <NODEPORT> -P <WORKERPORT> -t <TEST_BALANCE_RUN> -m file
#
# TEST_BALANCE_RUN is either "first" or "second"
# if -m file is set, the mrenclave will be read from file

while getopts ":m:p:P:t:u:V:C:a:A:" opt; do
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
        a)
            TARGET_A_RPC_PORT=$OPTARG
            ;;
        P)
            WORKER_1_PORT=$OPTARG
            ;;
        u)
            INTEGRITEE_RPC_URL=$OPTARG
            ;;
        A)
            TARGET_A_RPC_URL=$OPTARG
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

TARGET_A_RPC_PORT=${TARGET_A_RPC_PORT:-9954}
TARGET_A_RPC_URL=${TARGET_A_RPC_URL:-"ws://127.0.0.1"}

WORKER_1_PORT=${WORKER_1_PORT:-2000}
WORKER_1_URL=${WORKER_1_URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

echo "Using client binary ${CLIENT_BIN}"
${CLIENT_BIN} --version
echo "Using integritee node uri ${INTEGRITEE_RPC_URL}:${INTEGRITEE_RPC_PORT}"
echo "Using target_a node uri ${TARGET_A_RPC_URL}:${TARGET_A_RPC_PORT}"
echo "Using trusted-worker uri ${WORKER_1_URL}:${WORKER_1_PORT}"
echo ""

# the parentchain token is 12 decimal
UNIT=$(( 10 ** 12 ))
FEE_TOLERANCE=$((10 ** 11))

# make these amounts greater than ED
AMOUNT_SHIELD=$(( 6 * UNIT ))
AMOUNT_TRANSFER=$(( 2 * UNIT ))
AMOUNT_UNSHIELD=$(( 1 * UNIT ))

CLIENT="${CLIENT_BIN} -p ${INTEGRITEE_RPC_PORT} -P ${WORKER_1_PORT} -u ${INTEGRITEE_RPC_URL} -U ${WORKER_1_URL}"

# for talking to TARGET_A L1
CLIENT_A="${CLIENT_BIN} -p ${TARGET_A_RPC_PORT} -P ${WORKER_1_PORT} -u ${TARGET_A_RPC_URL} -U ${WORKER_1_URL}"

# offchain-worker only suppports indirect calls
CALLTYPE=
case "$FLAVOR_ID" in
    sidechain) CALLTYPE="--direct" ;;
    offchain-worker) : ;;
    *) CALLTYPE="--direct" ;;
esac
echo "using call type: ${CALLTYPE} (empty means indirect)"

# interval and max rounds to wait to check the given account balance in sidechain
WAIT_INTERVAL_SECONDS=6
WAIT_ROUNDS=20

# Poll and assert the given account's state is equal to expected,
# with timeout WAIT_INTERVAL_SECONDS * WAIT_ROUNDS
# usage:
#   wait_assert_state <mrenclave> <account> <state-name> <expected-state>
#   the `state-name` has to be the supported subcommand, e.g. `balance`, `nonce`
function wait_assert_state()
{
    for i in $(seq 1 $WAIT_ROUNDS); do
        sleep $WAIT_INTERVAL_SECONDS
        state=$(${CLIENT} trusted --mrenclave "$1" "$3" "$2")
        if (( $4 >= state ? $4 - state < FEE_TOLERANCE : state - $4 < FEE_TOLERANCE)); then
            return
        else
            echo -n "."
        fi
    done
    echo
    echo "Assert $2 $3 failed, expected = $4, actual = $state, tolerance = $FEE_TOLERANCE"
    exit 1
}

function wait_assert_state_target_a()
{
    for i in $(seq 1 $WAIT_ROUNDS); do
        sleep $WAIT_INTERVAL_SECONDS
        state=$(${CLIENT_A} "$2" "$1")
        if (( $4 >= state ? $4 - state < FEE_TOLERANCE : state - $4 < FEE_TOLERANCE)); then
            return
        else
            echo -n "."
        fi
    done
    echo
    echo "Assert $2 $3 failed, expected = $4, actual = $state, tolerance = $FEE_TOLERANCE"
    exit 1
}
# Do a live query and assert the given account's state is equal to expected
# usage:
#   assert_state <mrenclave> <account> <state-name> <expected-state>
function assert_state()
{
    state=$(${CLIENT} trusted --mrenclave "$1" "$3" "$2")
    if [ -z "$state" ]; then
        echo "Query $2 $3 failed"
        exit 1
    fi

    if [ $state -eq "$4" ]; then
        return
    fi
    echo
    echo "Assert $2 $3 failed, expected = $4, actual = $state"
    exit 1
}

echo "* Query on-chain enclave registry:"
${CLIENT} list-workers
echo ""

if [ "$READ_MRENCLAVE" = "file" ]
then
    read MRENCLAVE <<< $(cat ~/mrenclave.b58)
    echo "Reading MRENCLAVE from file: ${MRENCLAVE}"
else
    # this will always take the first MRENCLAVE found in the registry !!
    read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
    echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"
fi
[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }


echo "* Create a new incognito account for Bob"
ICGACCOUNTBOB=$(${CLIENT} trusted --mrenclave ${MRENCLAVE} new-account)
echo "  Bob's incognito account = ${ICGACCOUNTBOB}"
echo ""

echo "* Query shard vault account"
VAULT=$(${CLIENT} trusted get-shard-vault)
echo "  shard vault account = ${VAULT}"
echo ""

# Asssert the initial balance of Charlie incognito
# The initial balance of Bob incognito should always be 0, as Bob is newly created
BALANCE_INCOGNITO_CHARLIE=0
BALANCE_A_FERDIE=$(${CLIENT_A} balance //Ferdie)

case $TEST in
    first)
        wait_assert_state ${MRENCLAVE} //Charlie balance 0 ;;
    second)
        wait_assert_state ${MRENCLAVE} //Charlie balance $(( AMOUNT_SHIELD - AMOUNT_TRANSFER - AMOUNT_UNSHIELD ))
        BALANCE_INCOGNITO_CHARLIE=$(( AMOUNT_SHIELD - AMOUNT_TRANSFER - AMOUNT_UNSHIELD )) ;;
    *)
        echo "assuming first run of test"
        wait_assert_state ${MRENCLAVE} //Charlie balance 0 ;;
esac

echo "* Shield ${AMOUNT_SHIELD} tokens from TARGET_A to Charlie's account on L2"
${CLIENT_A} transfer //Alice //Charlie $((AMOUNT_SHIELD * 2))
${CLIENT_A} transfer //Charlie ${VAULT} ${AMOUNT_SHIELD}
echo ""

echo "* Wait and assert Charlie's L2 account balance... "
wait_assert_state ${MRENCLAVE} //Charlie balance $(( BALANCE_INCOGNITO_CHARLIE + AMOUNT_SHIELD ))
echo "✔ ok"

echo "* Wait and assert Bob's incognito account balance... "
wait_assert_state ${MRENCLAVE} ${ICGACCOUNTBOB} balance 0
echo "✔ ok"
echo ""

echo "* Send ${AMOUNT_TRANSFER} funds from Charlie's L2 account to Bob's incognito account"
$CLIENT trusted $CALLTYPE --mrenclave ${MRENCLAVE} transfer //Charlie ${ICGACCOUNTBOB} ${AMOUNT_TRANSFER}
echo ""

echo "* Wait and assert Charlie's L2 account balance... "
wait_assert_state ${MRENCLAVE} //Charlie balance $(( BALANCE_INCOGNITO_CHARLIE + AMOUNT_SHIELD - AMOUNT_TRANSFER ))
echo "✔ ok"

echo "* Wait and assert Bob's incognito account balance... "
wait_assert_state ${MRENCLAVE} ${ICGACCOUNTBOB} balance ${AMOUNT_TRANSFER}
echo "✔ ok"
echo ""

echo "* Un-shield ${AMOUNT_UNSHIELD} tokens from Charlie's incognito account to Ferie's L1 account"
${CLIENT} trusted $CALLTYPE --mrenclave ${MRENCLAVE} unshield-funds //Charlie //Ferdie ${AMOUNT_UNSHIELD}
echo ""

echo "* Wait and assert Charlie's incognito account balance... "
wait_assert_state ${MRENCLAVE} //Charlie balance $(( BALANCE_INCOGNITO_CHARLIE + AMOUNT_SHIELD - AMOUNT_TRANSFER - AMOUNT_UNSHIELD ))
echo "✔ ok"

echo "* Wait and assert Ferdie's Target A account balance... "
wait_assert_state_target_a //Ferdie balance $(( BALANCE_A_FERDIE + AMOUNT_UNSHIELD ))
echo "✔ ok"

echo "* Wait and assert Bob's incognito account balance... "
wait_assert_state ${MRENCLAVE} ${ICGACCOUNTBOB} balance ${AMOUNT_TRANSFER}
echo "✔ ok"

# Test the nonce handling, using Bob's incognito account as the sender as Charlie's
# balance needs to be verified in the second round while Bob is newly created each time

echo "* Create a new incognito account for Charlie"
ICGACCOUNTCHARLIE=$(${CLIENT} trusted --mrenclave ${MRENCLAVE} new-account)
echo "  Charlie's incognito account = ${ICGACCOUNTCHARLIE}"
echo ""


echo "* Assert Bob's incognito initial nonce..."
assert_state ${MRENCLAVE} ${ICGACCOUNTBOB} nonce 0
echo "✔ ok"
echo ""

echo "* Send 3 consecutive 0.2 UNIT balance Transfer Bob -> Charlie"
for i in $(seq 1 3); do
    # use direct calls so they are submitted to the top pool synchronously
    $CLIENT trusted $CALLTYPE --mrenclave ${MRENCLAVE} transfer ${ICGACCOUNTBOB} ${ICGACCOUNTCHARLIE} $(( AMOUNT_TRANSFER / 10 ))
done
echo ""

echo "* Assert Bob's incognito current nonce..."
wait_assert_state ${MRENCLAVE} ${ICGACCOUNTBOB} nonce 3
echo "✔ ok"
echo ""

echo "* Send a 2 UNIT balance Transfer Bob -> Charlie (that will fail)"
$CLIENT trusted $CALLTYPE --mrenclave ${MRENCLAVE} transfer ${ICGACCOUNTBOB} ${ICGACCOUNTCHARLIE} ${AMOUNT_TRANSFER}
echo ""

echo "* Assert Bob's incognito nonce..."
# the nonce should be increased nontheless, even for the failed tx
wait_assert_state ${MRENCLAVE} ${ICGACCOUNTBOB} nonce 4
echo "✔ ok"
echo ""

echo "* Send another 0.2 UNIT balance Transfer Bob -> Charlie"
$CLIENT trusted $CALLTYPE --mrenclave ${MRENCLAVE} transfer ${ICGACCOUNTBOB} ${ICGACCOUNTCHARLIE} $(( AMOUNT_TRANSFER / 10 ))
echo ""

echo "* Assert Bob's incognito nonce..."
wait_assert_state ${MRENCLAVE} ${ICGACCOUNTBOB} nonce 5
echo "✔ ok"
echo ""

echo "* Wait and assert Bob's incognito account balance... "
# in total 4 balance transfer should go through => 1.2 UNIT remaining
wait_assert_state ${MRENCLAVE} ${ICGACCOUNTBOB} balance $(( AMOUNT_TRANSFER * 6 / 10 ))
echo "✔ ok"

echo ""
echo "-----------------------"
echo "✔ The $TEST test passed!"
echo "-----------------------"
echo ""
