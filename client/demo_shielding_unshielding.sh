#!/bin/bash

# setup:
# run all on localhost:
#   substratee-node --dev --ws-port 9977 -lruntime=debug
#   substratee-worker init_shard
#   substratee-worker shielding-key
#   substratee-worker signing-key
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

echo "* Create a new on-chain account for Alice"
ACCOUNTALICEOC=$(${CLIENT} new-account)
echo "  Alice's on-chain account = ${ACCOUNTALICEOC}"
echo ""

echo "* Create a new on-chain account for Bob"
ACCOUNTBOBOC=$(${CLIENT} new-account)
echo "  Bob's on-chain account = ${ACCOUNTBOBOC}"
echo ""

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance ${ACCOUNTALICEOC}
echo ""

echo "* Get balance of Bob's on-chain account"
${CLIENT} balance ${ACCOUNTBOBOC}
echo ""

echo "* Fund Alice's on-chain account from faucet"
${CLIENT} faucet ${ACCOUNTALICEOC}
echo ""

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance ${ACCOUNTALICEOC}
echo ""

echo "* Create a new incognito account for Alice"
ICGACCOUNTALICE=$(${CLIENT} trusted new-account --mrenclave ${MRENCLAVE})
echo "  Alice's incognito account = ${ICGACCOUNTALICE}"
echo ""

echo "* Create a new incognito account for Bob"
ICGACCOUNTBOB=$(${CLIENT} trusted new-account --mrenclave ${MRENCLAVE})
echo "  Bob's incognito account = ${ICGACCOUNTBOB}"
echo ""

echo "* Fund Alice's incognito account"
${CLIENT} shield-funds ${ICGACCOUNTALICE} ${MRENCLAVE} 50
echo ""

exit 0


echo -n "Alice's incognito account balance"
${CLIENT} trusted balance ${ICGACCOUNTALICE} --mrenclave ${MRENCLAVE}

echo -n "Bob's incognito account balance"
${CLIENT} trusted balance ${ICGACCOUNTBOB} --mrenclave ${MRENCLAVE}

echo "* Send 40 funds from Alice's incognito account to Bob's incognito account"
$CLIENT trusted transfer ${ICGACCOUNTALICE} ${ICGACCOUNTBOB} 40 --mrenclave ${MRENCLAVE}

echo -n "Alice's incognito account balance"
${CLIENT} trusted balance ${ICGACCOUNTALICE} --mrenclave ${MRENCLAVE}

echo -n "Bob's incognito account balance"
${CLIENT} trusted balance ${ICGACCOUNTBOB} --mrenclave ${MRENCLAVE}

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


echo -n "receiver balance: "
$CLIENT trusted balance $account1p --mrenclave $MRENCLAVE

echo -n "sender balance:  "
$CLIENT trusted balance //AliceIncognito --mrenclave $MRENCLAVE
