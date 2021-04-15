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
#  demo_direct_call.sh <NODEPORT> <WORKERRPCPORT>

# using default port if none given as arguments
NPORT=${1:-9944}
RPORT=${2:-2000}

echo "Using node-port ${NPORT}"
echo "Using worker-rpc-port ${RPORT}"
echo ""

AMOUNTSHIELD=50000000000
AMOUNTTRANSFER=40000000000


CLIENT="./substratee-client -p ${NPORT} -P ${RPORT}"
# SW mode - hardcoded MRENCLAVE!
#echo "* Query on-chain enclave registry:"
#${CLIENT} list-workers
#echo ""

# does this work when multiple workers are in the registry?
#read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE:[[:space:]]/ { print $2 }')
read MRENCLAVE <<< $(cat ~/mrenclave.b58)

echo "* Create a new incognito account for Alice"
ICGACCOUNTALICE=//AliceIncognito
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

echo "Get balance of Alice's incognito account"
${CLIENT} trusted balance ${ICGACCOUNTALICE} --mrenclave ${MRENCLAVE}
echo ""

#send funds from Alice to bobs account
echo "* Send ${AMOUNTTRANSFER} funds from Alice's incognito account to Bob's incognito account"
$CLIENT trusted transfer ${ICGACCOUNTALICE} ${ICGACCOUNTBOB} ${AMOUNTTRANSFER} --mrenclave ${MRENCLAVE} --direct
echo ""

echo "* Get balance of Alice's incognito account"
${CLIENT} trusted balance ${ICGACCOUNTALICE} --mrenclave ${MRENCLAVE}
echo ""

echo "* Bob's incognito account balance"
${CLIENT} trusted balance ${ICGACCOUNTBOB} --mrenclave ${MRENCLAVE}
echo ""



# the following tests are for automated CI
# they only work if you're running from fresh genesis
case "$3" in
    first)
        if [ "10000000000" = "$RESULT" ]; then
            echo "test passed (1st time)"
            exit 0
        else
            echo "test ran through but balance is wrong. have you run the script from fresh genesis?"
            exit 1
        fi
        ;;
    second)
        if [ "20000000000" = "$RESULT" ]; then
            echo "test passed (2nd time)"
            exit 0
        else
            echo "test ran through but balance is wrong. is this really the second time you run this since genesis?"
            exit 1
        fi
        ;;
esac

exit 0