#!/bin/bash

# setup:
# run all on localhost:
#   substratee-node purge-chain --dev
#   substratee-node --dev --ws-port 9994 -lruntime=debug
#   rm chain_relay_db.bin
#   substratee-worker init_shard
#   substratee-worker shielding-key
#   substratee-worker signing-key
#   substratee-worker -P 2094 -r 3448 -p 9994 run
#
# then run this script

# usage:
#  demo_direct_call.sh <NODEPORT> <WORKERPORT>

# using default port if none given as first argument
NPORT=${1:-9994}
WPORT=${2:-2094}
RPORT=${2:-4000}

echo "Using node-port ${NPORT}"
echo "Using worker-port ${WPORT}"
echo "Using direct-rpc-port ${RPORT}"
echo ""

CLIENT="./substratee-client -p ${NPORT} -P ${WPORT} -R${RPORT}"

echo "* Query on-chain enclave registry:"
${CLIENT} list-workers
echo ""

# TODO: This does not work when multiple workers are in the registry
echo "* Reading MRENCLAVE of first worker"
read MRENCLAVE <<< $(${CLIENT} list-workers | awk '/  MRENCLAVE: / { print $2 }')
echo "  MRENCLAVE = ${MRENCLAVE}"
echo ""

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance "//Alice"
echo ""

echo "* Get balance of Bob's on-chain account"
${CLIENT} balance "//Bob"
echo ""

echo "* Create a new incognito account for Alice"
ICGACCOUNTALICE=$(${CLIENT} trusted new-account --mrenclave ${MRENCLAVE})
echo "  Alice's incognito account = ${ICGACCOUNTALICE}"
echo ""

echo "* Create a new incognito account for Bob"
ICGACCOUNTBOB=$(${CLIENT} trusted new-account --mrenclave ${MRENCLAVE})
echo "  Bob's incognito account = ${ICGACCOUNTBOB}"
echo ""

echo "* Shield ${AMOUNTSHIELD} tokens to Alice's incognito account"
${CLIENT} shield-funds //Alice ${ICGACCOUNTALICE} ${AMOUNTSHIELD} ${MRENCLAVE} ${WORKERPORT}
echo ""

echo "* Waiting 10 seconds"
sleep 10
echo ""

echo -n "Get balance of Alice's incognito account"
${CLIENT} trusted balance ${ICGACCOUNTALICE} --mrenclave ${MRENCLAVE}
echo ""

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance "//Alice"
echo ""

echo "* Send ${AMOUNTTRANSFER} funds from Alice's incognito account to Bob's incognito account"
$CLIENT trusted transfer ${ICGACCOUNTALICE} ${ICGACCOUNTBOB} ${AMOUNTTRANSFER} --mrenclave ${MRENCLAVE}
echo ""

echo "* Get balance of Alice's incognito account"
${CLIENT} trusted balance ${ICGACCOUNTALICE} --mrenclave ${MRENCLAVE}
echo ""

echo "* Bob's incognito account balance"
${CLIENT} trusted balance ${ICGACCOUNTBOB} --mrenclave ${MRENCLAVE}
echo ""

echo "* Un-shield ${AMOUNTUNSHIELD} tokens from Alice's incognito account"
${CLIENT} trusted unshield-funds ${ICGACCOUNTALICE} //Alice ${AMOUNTUNSHIELD} ${MRENCLAVE} --mrenclave ${MRENCLAVE} --xt-signer //Alice
echo ""

echo "* Waiting 10 seconds"
sleep 10
echo ""

echo -n "Get balance of Alice's incognito account"
${CLIENT} trusted balance ${ICGACCOUNTALICE} --mrenclave ${MRENCLAVE}
echo ""

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance "//Alice"
echo ""
