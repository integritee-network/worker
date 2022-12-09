#!/bin/bash
set -euo pipefail

trap "echo The demo is terminated (SIGINT); exit 1" SIGINT
trap "echo The demo is terminated (SIGTERM); exit 1" SIGTERM

# Registers a teeracle with the parentchain, and publish some oracle data.
#
# Demo to show that an enclave can update the exchange rate only when
#   1. the enclave is registered at the pallet-teerex.
#   2. and that the code used is reliable -> the enclave has been put the teeracle whitelist via a governance or sudo
#   call.
#
# The teeracle's whitelist has to be empty at the start. So the script needs to run with a clean node state.
# A registered mrenclave will be added in the whitelist by a sudo account. Here //Alice
#
# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --dev -lpallet_teeracle=debug,parity_ws=error,aura=error,sc_basic_authorship=error
#   integritee-service --clean-reset run (--skip-ra --dev)
#
# then run this script
#
# usage:
#   demo_teeracle_whitelist.sh -p <NODEPORT> -P <WORKERPORT> -d <DURATION> -i <WORKER_UPDATE_INTERVAL> -u <NODE_URL> -V <WORKER_URL> -C <CLIENT_BINARY_PATH>

while getopts ":p:P:d:i:u:V:C:" opt; do
    case $opt in
        p)
            NPORT=$OPTARG
            ;;
        P)
            WORKER1PORT=$OPTARG
            ;;
        d)
            DURATION=$OPTARG
            ;;
        i)
            INTERVAL=$OPTARG
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

# using default port if none given as arguments
NPORT=${NPORT:-9944}
NODEURL=${NODEURL:-"ws://127.0.0.1"}

WORKER1PORT=${WORKER1PORT:-2000}
WORKER1URL=${WORKER1URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

DURATION=${DURATION:-48}
INTERVAL=${INTERVAL:-86400}

LISTEN_TO_EXCHANGE_RATE_EVENTS_CMD="oracle listen-to-exchange-rate-events"
ADD_TO_WHITELIST_CMD="oracle add-to-whitelist"

echo "Using client binary ${CLIENT_BIN}"
echo "Using node uri ${NODEURL}:${NPORT}"
echo "Using trusted-worker uri ${WORKER1URL}:${WORKER1PORT}"
echo "Using worker market data update interval ${INTERVAL}"
echo "Count the update events for ${DURATION}"
echo ""

COIN_GECKO="https://api.coingecko.com/"
COIN_MARKET_CAP="https://pro-api.coinmarketcap.com/"
let "MIN_EXPECTED_NUM_OF_EVENTS=$DURATION/$INTERVAL-3"
echo "Minimum expected number of events with a single oracle source: ${MIN_EXPECTED_NUM_OF_EVENTS}"

let "MIN_EXPECTED_NUM_OF_EVENTS_2 = 2*$MIN_EXPECTED_NUM_OF_EVENTS"
echo "Minimum expected number of events with two oracle sources: ${MIN_EXPECTED_NUM_OF_EVENTS_2}"

CLIENT="${CLIENT_BIN} -p ${NPORT} -P ${WORKER1PORT} -u ${NODEURL} -U ${WORKER1URL}"

echo "* Query on-chain enclave registry:"
${CLIENT} list-workers
echo ""

# this will always take the first MRENCLAVE found in the registry !!
read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"

[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }
echo ""

echo "Listen to ExchangeRateUpdated events for ${DURATION} seconds. There should be no trusted oracle source!"
#${CLIENT} ${LISTEN_TO_EXCHANGE_RATE_EVENTS_CMD} ${DURATION}
#echo ""

read NO_EVENTS <<< $(${CLIENT} ${LISTEN_TO_EXCHANGE_RATE_EVENTS_CMD} ${DURATION} | awk '/  EVENTS_COUNT: / { print $2; exit }')
echo "Got ${NO_EVENTS} exchange rate updates when no trusted oracle source is in the whitelist"
echo ""

echo "Add ${COIN_GECKO} for ${MRENCLAVE} as trusted oracle source"
${CLIENT} ${ADD_TO_WHITELIST_CMD} //Alice ${COIN_GECKO} ${MRENCLAVE}
echo "MRENCLAVE in whitelist for ${COIN_GECKO}"
echo ""

echo "Listen to ExchangeRateUpdated events for ${DURATION} seconds, after a trusted oracle source has been added to the whitelist."
#${CLIENT} ${LISTEN_TO_EXCHANGE_RATE_EVENTS_CMD} ${DURATION}
#echo ""

read EVENTS_COUNT <<< $($CLIENT ${LISTEN_TO_EXCHANGE_RATE_EVENTS_CMD} ${DURATION} | awk '/  EVENTS_COUNT: / { print $2; exit }')
echo "Got ${EVENTS_COUNT} exchange rate updates from the trusted oracle source in ${DURATION} second(s)"
echo ""

echo "Add ${COIN_MARKET_CAP} for ${MRENCLAVE} as trusted oracle source"
${CLIENT} ${ADD_TO_WHITELIST_CMD} //Alice ${COIN_MARKET_CAP} ${MRENCLAVE}
echo "MRENCLAVE in whitelist for ${COIN_MARKET_CAP}"
echo ""

echo "Listen to ExchangeRateUpdated events for ${DURATION} seconds, after a second trusted oracle source has been added to the whitelist."
#${CLIENT} ${LISTEN_TO_EXCHANGE_RATE_EVENTS_CMD} ${DURATION}
#echo ""

read EVENTS_COUNT_2 <<< $($CLIENT ${LISTEN_TO_EXCHANGE_RATE_EVENTS_CMD} ${DURATION} | awk '/  EVENTS_COUNT: / { print $2; exit }')
echo "Got ${EVENTS_COUNT_2} exchange rate updates from 2 trusted oracle sources in ${DURATION} second(s)"
echo ""

echo "Results :"

# the following test is for automated CI
# it only works if the teeracle's whitelist is empty at the start (run it from genesis)
if [ $EVENTS_COUNT_2 -ge $MIN_EXPECTED_NUM_OF_EVENTS_2 ]; then
   if [ $EVENTS_COUNT -ge $MIN_EXPECTED_NUM_OF_EVENTS ]; then
       if [ 0 -eq $NO_EVENTS ]; then
           echo "test passed"
           exit 0
       else
           echo "The test ran through but we received ExchangeRateUpdated events before the enclave was added to the whitelist. Was the enclave previously whitelisted? Perhaps by another teeracle?"
           exit 1
      fi
   else
    echo "test failed: Not enough events received for single oracle source: $EVENTS_COUNT. Should be greater than $MIN_EXPECTED_NUM_OF_EVENTS"
    exit 1
   fi
else
    echo "test failed: Not enough events received for 2 oracle sources: $EVENTS_COUNT_2. Should be greater than $MIN_EXPECTED_NUM_OF_EVENTS_2"
    exit 1
fi

exit 1
