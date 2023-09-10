#!/bin/bash
set -euo pipefail

# Verifies that shielding from the Target A and B parentchains works by sending a transfer to //Alice.
#
# Note: This test does not do anything meaningful. It only verifies the basic functionality of the Target parentchain
# connections.

while getopts ":m:p:A:u:V:w:x:y:z:C:" opt; do
    case $opt in
        p)
            INTEGRITEE_RPC_PORT=$OPTARG
            ;;
        A)
            WORKER_1_PORT=$OPTARG
            ;;
        u)
            INTEGRITEE_RPC_URL=$OPTARG
            ;;
        V)
            WORKER_1_URL=$OPTARG
            ;;
        w)
            TARGET_A_PARENTCHAIN_RPC_URL=$OPTARG
            ;;
        x)
            TARGET_A_PARENTCHAIN_RPC_PORT=$OPTARG
            ;;
        y)
            TARGET_B_PARENTCHAIN_RPC_URL=$OPTARG
            ;;
        z)
            TARGET_B_PARENTCHAIN_RPC_PORT=$OPTARG
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
TARGET_A_PARENTCHAIN_RPC_PORT=${TARGET_A_PARENTCHAIN_RPC_PORT:-9966}
TARGET_A_PARENTCHAIN_RPC_URL=${TARGET_A_PARENTCHAIN_RPC_URL:-"ws://127.0.0.1"}
TARGET_B_PARENTCHAIN_RPC_PORT=${TARGET_B_PARENTCHAIN_RPC_PORT:-9988}
TARGET_B_PARENTCHAIN_RPC_URL=${TARGET_B_PARENTCHAIN_RPC_URL:-"ws://127.0.0.1"}

WORKER_1_PORT=${WORKER_1_PORT:-2000}
WORKER_1_URL=${WORKER_1_URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

echo "Using client binary ${CLIENT_BIN}"
${CLIENT_BIN} --version
echo "Using Integritee RPC uri ${INTEGRITEE_RPC_URL}:${INTEGRITEE_RPC_PORT}"
echo "Using Target A RPC uri ${TARGET_A_PARENTCHAIN_RPC_URL}:${TARGET_A_PARENTCHAIN_RPC_PORT}"
echo "Using Target B RPC uri ${TARGET_B_PARENTCHAIN_RPC_URL}:${TARGET_B_PARENTCHAIN_RPC_PORT}"
echo "Using trusted-worker 1 uri ${WORKER_1_URL}:${WORKER_1_PORT}"
echo ""

# the parentchain token is 12 decimal
UNIT=$(( 10 ** 12 ))

# make these amounts greater than ED
AMOUNT_SHIELD=$(( 6 * UNIT ))

CLIENT="${CLIENT_BIN} -p ${INTEGRITEE_RPC_PORT} -P ${WORKER_1_PORT} -u ${INTEGRITEE_RPC_URL} -U ${WORKER_1_URL}"
CLIENT2="${CLIENT_BIN} -p ${TARGET_A_PARENTCHAIN_RPC_PORT} -P ${WORKER_1_PORT} -u ${TARGET_A_PARENTCHAIN_RPC_URL} -U ${WORKER_1_URL}"
CLIENT3="${CLIENT_BIN} -p ${TARGET_B_PARENTCHAIN_RPC_PORT} -P ${WORKER_1_PORT} -u ${TARGET_B_PARENTCHAIN_RPC_URL} -U ${WORKER_1_URL}"

# interval and max rounds to wait to check the given account balance in sidechain
WAIT_INTERVAL_SECONDS=10
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
        if [ $state -eq "$4" ]; then
            return
        else
            :
        fi
    done
    echo
    echo "Assert $2 $3 failed, expected = $4, actual = $state"
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

# this will always take the first MRENCLAVE found in the registry !!
read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"

[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }

ALICETRUSTEDACCOUNT=//Alice
echo "  Alice's trusted account (same as public account) = ${ALICETRUSTEDACCOUNT}"
echo ""

# Assert the initial trusted balance of Alice incognito
TRUSTED_BALANCE_ALICE=1000000000000000
wait_assert_state ${MRENCLAVE} ${ALICETRUSTEDACCOUNT} balance ${TRUSTED_BALANCE_ALICE}


echo "* Send ${AMOUNT_SHIELD} from //Alice to //Alice on the Target A parentchain, which should trigger the shield process"
${CLIENT2} transfer //Alice ${ALICETRUSTEDACCOUNT} ${AMOUNT_SHIELD}
echo ""

echo "* Wait and assert Alice's incognito account balance, should be $(( TRUSTED_BALANCE_ALICE + AMOUNT_SHIELD ))"
wait_assert_state ${MRENCLAVE} ${ALICETRUSTEDACCOUNT} balance $(( TRUSTED_BALANCE_ALICE + AMOUNT_SHIELD ))
echo "✔ ok"

echo "* Send ${AMOUNT_SHIELD} from //Alice to //Alice on the Target B Parentchain, which should trigger the shield process again"
${CLIENT3} transfer //Alice ${ALICETRUSTEDACCOUNT} ${AMOUNT_SHIELD}
echo ""

echo "* Wait and assert Alice's incognito account balance, should be $(( TRUSTED_BALANCE_ALICE + 2*AMOUNT_SHIELD ))"
wait_assert_state ${MRENCLAVE} ${ALICETRUSTEDACCOUNT} balance $(( TRUSTED_BALANCE_ALICE + 2*AMOUNT_SHIELD ))
echo "✔ ok"

echo ""
echo "-----------------------"
echo "✔ The test passed!"
echo "-----------------------"
echo ""
