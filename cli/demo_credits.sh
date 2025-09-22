#!/bin/bash
# usage:
#  demo_credits.sh -p <NODEPORT> -P <WORKERPORT>
#

while getopts ":p:P:u:V:C:" opt; do
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

CLIENT="${CLIENT_BIN} -p ${INTEGRITEE_RPC_PORT} -P ${WORKER_1_PORT} -u ${INTEGRITEE_RPC_URL} -U ${WORKER_1_URL}"
# we simply believe the enclave here without verifying the teerex RA
MRENCLAVE="$($CLIENT trusted get-fingerprint)"
echo "Using MRENCLAVE: ${MRENCLAVE}"
TCLIENT="${CLIENT} trusted --mrenclave ${MRENCLAVE} --direct"

# clean up from previous runs
${TCLIENT} credits destroy-class //Alice 42 || true

${TCLIENT} credits create-class //Alice 42
${TCLIENT} credits get-credit-class-info //Alice 42

echo "Bob creates a commitment and requests credits from Alice"
OUTPUT=$(${TCLIENT} credits generate-commitment)
echo $OUTPUT
# Extract the secret and commitment values
SECRET=$(echo "$OUTPUT" | grep 'secret:' | awk '{print $2}')
COMMITMENT=$(echo "$OUTPUT" | grep 'commitment:' | awk '{print $2}')

echo "Alice mints credits fro Bob's commitment $COMMITMENT"
${TCLIENT} credits mint //Alice 42 ${COMMITMENT} 123
${TCLIENT} credits get-credit-class-info //Alice 42

echo "Bob claims unlinkably by revealing his SECRET $SECRET"
${TCLIENT} credits claim //Bob 42 ${SECRET}
OUTPUT=$(${TCLIENT} credits get-credits //Bob 42)
BALANCE=$(echo "$OUTPUT" | grep -o 'balance: [0-9]*' | awk '{print $2}')
echo "Bob's balance after claiming: $BALANCE"
# Exit if balance does not match 123
if [[ "$BALANCE" != "123" ]]; then
    echo "Error: balance is $BALANCE, expected 123"
    exit 1
fi

echo "Bob redeems 3 credits"
${TCLIENT} credits redeem //Alice 42 //Bob 3

OUTPUT=$(${TCLIENT} credits get-credits //Bob 42)
BALANCE=$(echo "$OUTPUT" | grep -o 'balance: [0-9]*' | awk '{print $2}')
echo "Bob's balance after redeeming 3 credits: $BALANCE"
# Exit if balance does not match 123
if [[ "$BALANCE" != "120" ]]; then
    echo "Error: balance is $BALANCE, expected 120"
    exit 1
fi

${TCLIENT} credits destroy-class //Alice 42

exit 0
