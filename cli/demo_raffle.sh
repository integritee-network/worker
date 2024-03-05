#!/bin/bash
set -euo pipefail

# Creates a merkle-root of a set of orders and verifies the proof afterwards.
#
# Note this script is the basis for a full fledget demo of the energy market.
# Things that are missing:
#   * Perform the pay as bid operation
#   * Check the merkle root hash on chain
#
#
# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --tmp --dev -lruntime=debug
#   rm light_client_db.bin
#   export RUST_LOG=integritee_service=info,ita_stf=debug
#   integritee-service init_shard
#   integritee-service run
#
# then run this script

# usage:
#  demo_energy_market.sh -p <NODEPORT> -P <WORKERPORT> -t -O <path-to-order-file>

while getopts ":p:A:P:u:V:C:I:O:T:" opt; do
    case $opt in
        p)
            NPORT=$OPTARG
            ;;
        A)
            WORKER1PORT=$OPTARG
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
        I)
            ACTOR_ID=$OPTARG
            ;;
        O)
            ORDERS_FILE=$OPTARG
            ;;
        T)
            TIMESTAMP=$OPTARG
            ;;
        *)
            echo "Invalid Argument Supplied"
            exit 1
            ;;
    esac
done

# Using default port if none given as arguments.
NPORT=${NPORT:-9944}
NODEURL=${NODEURL:-"ws://127.0.0.1"}

WORKER1PORT=${WORKER1PORT:-2000}
WORKER1URL=${WORKER1URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

RAFFLE_INDEX=0
WINNER_COUNT=2

echo "Using client binary ${CLIENT_BIN}"
echo "Using node uri ${NODEURL}:${NPORT}"
echo "Using trusted-worker uri ${WORKER1URL}:${WORKER1PORT}"
echo "Using raffle index ${RAFFLE_INDEX}"
echo ""

echo "* Query the first registered raffle TEE onchain"
CLIENT="${CLIENT_BIN} -p ${NPORT} -P ${WORKER1PORT} -u ${NODEURL} -U ${WORKER1URL}"
read -r MRENCLAVE <<< "$($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')"

# Create Raffle
echo "* Alice creates a raffle"
RESULT=`$CLIENT trusted --mrenclave ${MRENCLAVE} --direct add-raffle //Alice ${WINNER_COUNT}`
echo "Result: ${RESULT}"

echo "* All ongoing raffles"
RESULT=`$CLIENT trusted --mrenclave ${MRENCLAVE} --direct get-all-raffles`
echo "Result: ${RESULT}"

# Have some users register for the raffle
USER_COUNT=50
echo "* Registering ${USER_COUNT} users for the for raffle number :${RAFFLE_INDEX}..."

for ((i=1; i<=USER_COUNT; i++)); do
  # Register 200 users in the background
  RESULT=$($CLIENT trusted --mrenclave "$MRENCLAVE" --direct register-for-raffle "//RaffleUser${i}" "$RAFFLE_INDEX") &
done

# await background processes
wait
echo "Registered ${USER_COUNT} users"

# ensure the next parentchain block is created so that we get a separate block for the draw winners event
sleep 12

# Draw winners
echo "* Draw the Winners"
RESULT=`$CLIENT trusted --mrenclave ${MRENCLAVE} --direct draw-winners //Alice ${RAFFLE_INDEX}`
echo "Result: ${RESULT}"

# Get and verify the registration
echo "* Get and verify the registration proofs"

echo "* Verify the a users registration"
RESULT=`$CLIENT trusted --mrenclave ${MRENCLAVE} --direct get-and-verify-registration-proof //RaffleUser10 ${RAFFLE_INDEX}`
echo "Result: ${RESULT}"
echo ""
