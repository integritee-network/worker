#!/bin/bash

# setup:
# run all on localhost:
#   substratee-node --dev --ws-port 9977 -lruntime=debug
#   TODO: MISSING STEPS FOR WORKER (shielding_key, shard, ...)
#   substratee-worker -p 9977 run
#
# then run this script

# using default port if none given as first argument
PORT=${1:-9944}

echo "Using port ${PORT}"
echo ""

CLIENT="./target/release/substratee-client -p ${PORT} "

echo "* Query on-chain enclave registry:"
${CLIENT} list-workers
echo ""

# TODO: This does not work when multiple workers are in the registry
echo "* Reading MRENCLAVE of first worker"
read MRENCLAVE <<< $(${CLIENT} list-workers | awk '/  MRENCLAVE:[[:space:]]/ { print $2 }')
echo "  MRENCLAVE = ${MRENCLAVE}"
echo ""

# echo "* Create a new on-chain account and fund it from faucet"
# OCACCOUNT=$(${CLIENT} new-account)
# echo "  On-chain account = ${OCACCOUNT}"
# echo ""
# echo "  ** Funding that account from faucet"
# $CLIENT faucet ${OCACCOUNT}
# echo ""

# echo "* Get balance of new on-chain account"
# ${CLIENT} balance ${OCACCOUNT}
# echo ""

echo "* Get balance of //Alice's on-chain account"
${CLIENT} balance //Alice
echo ""

echo "* Create a new incognito account"
ICGACCOUNT=$(${CLIENT} trusted new-account --mrenclave ${MRENCLAVE})
echo "  Incognito account = ${ICGACCOUNT}"
echo ""

echo "* Fund the incognito account"
${CLIENT} shield-funds ${ICGACCOUNT} ${MRENCLAVE} 50
echo ""

exit 0

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
