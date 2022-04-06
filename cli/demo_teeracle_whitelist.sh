#!/bin/bash

# Demo to show that an enclave can update the exchange rate only when
#   1. it is a registered enclave
#   2. and that the code used is reliable -> the enclave is in the teeracle whitelist.
# The teeracle's whitelist has to be empty at the start. So run it with a clean node state
# A registered mrenclave will be added in the whitelist by a sudo account. Here //Alice

# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --dev -lpallet_teeracle=debug,parity_ws=error,aura=error,sc_basic_authorship=error
#   integritee-service init_shard
#   integritee-service shielding-key
#   integritee-service signing-key
#   integritee-service run
#
# then run this script

# usage:
#   demo_teeracle_whitelist.sh -p <NODEPORT> -P <WORKERPORT> -d <DURATION> -i <WORKER_UPDATE_INTERVAL>

while getopts ":p:P:d:i:" opt; do
    case $opt in
        p)
            NPORT=$OPTARG
            ;;
        P)
            RPORT=$OPTARG
            ;;
        d)
            DURATION=$OPTARG
            ;;
        i)
            INTERVAL=$OPTARG
            ;;
    esac
done

# using default port if none given as arguments
NPORT=${NPORT:-9944}
RPORT=${RPORT:-2000}
DURATION=${DURATION:-48}
INTERVAL=${INTERVAL:-86400}

echo "Using node-port ${NPORT}"
echo "Using worker-rpc-port ${RPORT}"
echo "Using worker market data update interval ${INTERVAL}"
echo "Count the update events for ${DURATION}"
echo ""

COIN_GECKO="https://api.coingecko.com/"
COIN_MARKET_CAP="https://pro-api.coinmarketcap.com/"
let "MIN_EXPECTED_NUM_OF_EVENTS=$DURATION/$INTERVAL-1"
echo "MIN_EXPECTED_NUM_OF_EVENTS ${MIN_EXPECTED_NUM_OF_EVENTS}"

let "MIN_EXPECTED_NUM_OF_EVENTS_2 = 2*$MIN_EXPECTED_NUM_OF_EVENTS"
echo "MIN_EXPECTED_NUM_OF_EVENTS_2 ${MIN_EXPECTED_NUM_OF_EVENTS_2}"

CLIENT="./../bin/integritee-cli -p ${NPORT} -P ${RPORT}"

echo "* Query on-chain enclave registry:"
${CLIENT} list-workers
echo ""

# this will always take the first MRENCLAVE found in the registry !!
read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"

[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }
echo ""

echo "Listen to ExchangeRateUpdated events for ${DURATION} seconds. There should be no trusted oracle service!"
${CLIENT} exchange-rate-events ${DURATION}
echo ""

read NO_EVENTS <<< $($CLIENT exchange-rate-events ${DURATION} | awk '/  EVENTS_COUNT: / { print $2; exit }')
echo "Got ${NO_EVENTS} exchange rate updates when no trusted oracle service is in the whitelist"
echo ""

echo "Add MRENCLAVE as trusted oracle service for ${COIN_GECKO}"
${CLIENT} add-whitelist //Alice ${COIN_GECKO} ${MRENCLAVE}
echo "MRENCLAVE in Whitelist for ${COIN_GECKO}"
echo ""

echo "Listen to ExchangeRateUpdated events for ${DURATION} seconds, after a trusted oracle service has been added to the whitelist."
${CLIENT} exchange-rate-events ${DURATION}
echo ""

read EVENTS_COUNT <<< $($CLIENT exchange-rate-events ${DURATION} | awk '/  EVENTS_COUNT: / { print $2; exit }')
echo "Got ${EVENTS_COUNT} exchange rate updates from the trusted oracle service in ${DURATION} second"
echo ""




echo "Add MRENCLAVE as trusted oracle service for ${COIN_MARKET_CAP}"
${CLIENT} add-whitelist //Alice ${COIN_MARKET_CAP} ${MRENCLAVE}
echo "MRENCLAVE in Whitelist for ${COIN_MARKET_CAP}"
echo ""

echo "Listen to ExchangeRateUpdated events for ${DURATION} seconds, after a second trusted oracle service has been added to the whitelist."
${CLIENT} exchange-rate-events ${DURATION}
echo ""

read EVENTS_COUNT_2 <<< $($CLIENT exchange-rate-events ${DURATION} | awk '/  EVENTS_COUNT: / { print $2; exit }')
echo "Got ${EVENTS_COUNT_2} exchange rate updates from 2 trusted oracle services in ${DURATION} second"
echo ""


# the following test is for automated CI
# it only works if the teeracle's whitelist is empty at the start (run it from genesis)
if [ "$EVENTS_COUNT_2" > "$MIN_EXPECTED_NUM_OF_EVENTS_2" ]; then
   if [ "$EVENTS_COUNT" > "$MIN_EXPECTED_NUM_OF_EVENTS" ]; then
       if [ "0" = "$NO_EVENTS" ]; then
           echo "test passed"
           exit 0
       else
           echo "The test ran through but we received ExchangeRateUpdated events before the enclave was added to the whitelist. Was the enclave previously whitelisted? Perhaps by another teeracle?"
           exit 1
      fi
   else
    echo "test failed: $MIN_EXPECTED_NUM_OF_EVENTS!< $EVENTS_COUNT"
    exit 1
   fi
else
    echo "test failed: $MIN_EXPECTED_NUM_OF_EVENTS_2 !< $EVENTS_COUNT_2 "
    exit 1
fi

exit 0
