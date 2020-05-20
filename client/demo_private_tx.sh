#!/bin/bash

# setup:
# run all on localhost:
# run substratee-node --dev --ws-port 9979 -lruntime=debug
# run substratee-worker -p 9979 run
#
# then run this script

CLIENT="../target/release/substratee-client -p 9979"

echo "query on-chain enclave registry:"
$CLIENT list-workers
echo ""

# does this work when multiple workers are in the registry?
read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE:[[:space:]]/ { print $2 }')

# only for initial setup (actually should be done in genesis)
# pre-fund //AliceIncognito, our ROOT key
echo "issue funds on first (sender) account:"
$CLIENT trusted set-balance //AliceIncognito 123456789 --mrenclave $MRENCLAVE
echo -n "get balance: "
$CLIENT trusted balance //AliceIncognito --mrenclave $MRENCLAVE

## create a new on-chain account and fund it form faucet
#account1=$($CLIENT new-account)
#echo "*** created new on-chain account: $account1"
#echo "*** funding that account from faucet"
#$CLIENT faucet $account1 

# create incognito account for default shard (= MRENCLAVE)
account1p=$($CLIENT trusted new-account --mrenclave $MRENCLAVE)
echo "created new incognito account: $account1p"

#send 10M funds from AliceIncognito to new account
$CLIENT trusted transfer //AliceIncognito $account1p 23456789 --mrenclave $MRENCLAVE

echo -n "receiver balance: "
$CLIENT trusted balance $account1p --mrenclave $MRENCLAVE

echo -n "sender balance:  "
$CLIENT trusted balance //AliceIncognito --mrenclave $MRENCLAVE
