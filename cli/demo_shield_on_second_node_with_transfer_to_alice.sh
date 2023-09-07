#!/bin/bash
set -euo pipefail

# Verifies that shielding from a secondary parentchain works by sending a transfer to //Alice

while getopts ":m:p:A:B:u:W:V:x:y:C:" opt; do
    case $opt in
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
        u)
            NODEURL=$OPTARG
            ;;
        V)
            WORKER1URL=$OPTARG
            ;;
        W)
            WORKER2URL=$OPTARG
            ;;
        x)
            NODE2URL=$OPTARG
            ;;
        y)
            NODE2PORT=$OPTARG
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
NPORT=${NPORT:-9944}
NODEURL=${NODEURL:-"ws://127.0.0.1"}
NODE2PORT=${NODE2PORT:-9966}
NODE2URL=${NODE2URL:-"ws://127.0.0.1"}

WORKER1PORT=${WORKER1PORT:-2000}
WORKER1URL=${WORKER1URL:-"wss://127.0.0.1"}

WORKER2PORT=${WORKER2PORT:-3000}
WORKER2URL=${WORKER2URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

echo "Using client binary ${CLIENT_BIN}"
${CLIENT_BIN} --version
echo "Using node uri ${NODEURL}:${NPORT}"
echo "Using node 2 uri ${NODE2URL}:${NODE2PORT}"
echo "Using trusted-worker 1 uri ${WORKER1URL}:${WORKER1PORT}"
echo "Using trusted-worker 2 uri ${WORKER2URL}:${WORKER2PORT}"
echo ""

# the parentchain token is 12 decimal
UNIT=$(( 10 ** 12 ))

# make these amounts greater than ED
AMOUNT_SHIELD=$(( 6 * UNIT ))
AMOUNT_TRANSFER=$(( 2 * UNIT ))
AMOUNT_UNSHIELD=$(( 1 * UNIT ))

CLIENT="${CLIENT_BIN} -p ${NPORT} -P ${WORKER1PORT} -u ${NODEURL} -U ${WORKER1URL}"
CLIENT2="${CLIENT_BIN} -p ${NODE2PORT} -P ${WORKER1PORT} -u ${NODE2URL} -U ${WORKER1URL}"

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


echo "* Send ${AMOUNT_SHIELD} from //Alice to //Alice on L1, which should trigger the demo shield process"
${CLIENT2} transfer //Alice ${ALICETRUSTEDACCOUNT} ${AMOUNT_SHIELD}
echo ""

echo "* Wait and assert Alice's incognito account balance, should be $(( TRUSTED_BALANCE_ALICE + AMOUNT_SHIELD ))"
wait_assert_state ${MRENCLAVE} ${ALICETRUSTEDACCOUNT} balance $(( TRUSTED_BALANCE_ALICE + AMOUNT_SHIELD ))
echo "✔ ok"

echo ""
echo "-----------------------"
echo "✔ The test passed!"
echo "-----------------------"
echo ""
