#!/bin/bash

# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --tmp --dev -lruntime=debug
#   rm light_client_db.bin
#   export RUST_LOG=integritee_service=info,ita_stf=debug
#   integritee-service init_shard
#   integritee-service shielding-key
#   integritee-service signing-key
#   integritee-service run
#
# then run this script

# usage:
#  export RUST_LOG_LOG=integritee-cli=info,ita_stf=info
#  demo_private_tx.sh <NODEPORT> <WORKERRPCPORT>

# using default port if none given as arguments
NPORT=${1:-9944}
RPORT=${3:-2000}

echo "Using node-port ${NPORT}"
echo "Using worker-rpc-port ${RPORT}"
echo ""

CLIENT="./../bin/integritee-cli -p ${NPORT} -P ${RPORT}"
# SW mode - hardcoded MRENCLAVE!
read MRENCLAVE <<< $(cat ~/mrenclave.b58)

# only for initial setup (actually should be done in genesis)
# pre-fund //AliceIncognito, our ROOT key
echo "issue funds on first (sender) account:"
$CLIENT trusted set-balance //AliceIncognito 123456789 --mrenclave $MRENCLAVE
echo -n "get balance: "
$CLIENT trusted balance //AliceIncognito --mrenclave $MRENCLAVE

# create incognito account for default shard (= MRENCLAVE)
account1p=$($CLIENT trusted new-account --mrenclave $MRENCLAVE)
echo "created new incognito account: $account1p"

#send 10M funds from AliceIncognito to new account
$CLIENT trusted transfer //AliceIncognito $account1p 23456789 --mrenclave $MRENCLAVE

echo -n "receiver balance: "
$CLIENT trusted balance $account1p --mrenclave $MRENCLAVE

echo -n "sender balance:  "
$CLIENT trusted balance //AliceIncognito --mrenclave $MRENCLAVE
