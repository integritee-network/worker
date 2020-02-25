#!/bin/bash

# setup:
# run all on localhost:
# run substratee-node --dev --ws-port 9979 -lruntime=debug
# run substratee-worker -p 9979 run
#
# then run this script

CLIENT="../target/release/substratee-client -p 9979 "

$CLIENT list-workers

# does this work when multiple workers are in the registry?
read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE:[[:space:]]/ { print $2 }')

# only for initial setup (actually should be done in genesis)
# pre-fund //AliceIncognito, our ROOT key
$CLIENT trusted set-balance //AliceIncognito 1000000000 --mrenclave $MRENCLAVE
echo "get AliceIncognito balance:"
$CLIENT trusted balance //AliceIncognito --mrenclave $MRENCLAVE

# create a new on-chain account and fund it form faucet
account1=$($CLIENT new-account)
echo "*** created new on-chain account: $account1"
echo "*** funding that account from faucet"
$CLIENT faucet $account1 

# create incognito account for default shard (= MRENCLAVE)
account1p=$($CLIENT trusted new-account --mrenclave $MRENCLAVE)
echo "*** created new incognito account: $account1p"

#send 10M funds from AliceIncognito to new account
$CLIENT trusted transfer //AliceIncognito $account1p 10000000 --mrenclave $MRENCLAVE

echo "balance on new account after transfer"
$CLIENT trusted balance $account1p --mrenclave $MRENCLAVE
