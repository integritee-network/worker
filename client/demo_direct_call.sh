#!/bin/bash

# setup:
# run all on localhost:
#   substratee-node purge-chain --dev
#   substratee-node --tmp --dev -lruntime=debug
#   rm chain_relay_db.bin
#   substratee-worker init_shard
#   substratee-worker shielding-key
#   substratee-worker signing-key
#   substratee-worker run
#
# then run this script

# usage:
#  demo_direct_call.sh <NODEPORT> <WORKERPORT> <WORKERRPCPORT>

# using default port if none given as arguments
NPORT=${1:-9944}
RPORT=${3:-4000}

echo "Using node-port ${NPORT}"
echo "Using worker-rpc-port ${RPORT}"
echo ""

CLIENT="./../bin/substratee-client -p ${NPORT} -R ${RPORT}"
# SW mode - hardcoded MRENCLAVE!
#echo "* Query on-chain enclave registry:"
#${CLIENT} list-workers
#echo ""

# does this work when multiple workers are in the registry?
#read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE:[[:space:]]/ { print $2 }')
read MRENCLAVE <<< $(cat ~/mrenclave.b58)

# only for initial setup (actually should be done in genesis)
# pre-fund //AliceIncognito, our ROOT key
echo "issue funds on first (sender) account:"
$CLIENT trusted set-balance //AliceIncognito 123456789 --mrenclave $MRENCLAVE --direct
echo -n "get balance: "
$CLIENT trusted balance //AliceIncognito --mrenclave $MRENCLAVE

# create incognito account for default shard (= MRENCLAVE)
account1p=$($CLIENT trusted new-account --mrenclave $MRENCLAVE)
echo "created new incognito account: $account1p"

#send 10M funds from AliceIncognito to new account
$CLIENT trusted transfer //AliceIncognito $account1p 23456789 --mrenclave $MRENCLAVE --direct

echo -n "receiver balance: "
$CLIENT trusted balance $account1p --mrenclave $MRENCLAVE

echo -n "sender balance:  "
$CLIENT trusted balance //AliceIncognito --mrenclave $MRENCLAVE
