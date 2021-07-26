#!/bin/bash

# setup:
# run all on localhost:
#   substratee-node purge-chain --dev
#   substratee-node --dev -lruntime=debug
#   rm chain_relay_db.bin
#   substratee-worker init_shard
#   substratee-worker shielding-key
#   substratee-worker signing-key
#   substratee-worker run
#
# then run this script

# usage:
#  demo_shielding_unshielding.sh -p <NODEPORT> -P <WORKERPORT> -t <TEST_BALANCE_RUN> -m file
#
# TEST_BALANCE_RUN is either "first" or "second"
# if -m file is set, the mrenclave will be read from file

while getopts ":m:p:P:t:" opt; do
    case $opt in
        t)
            TEST=$OPTARG
            ;;
        m)
            READMRENCLAVE=$OPTARG
            ;;
        p)
            NPORT=$OPTARG
            ;;
        P)
            RPORT=$OPTARG
            ;;
    esac
done

# using default port if none given as arguments
NPORT=${NPORT:-9944}
RPORT=${RPORT:-2000}

echo "Using node-port ${NPORT}"
echo "Using worker-rpc-port ${RPORT}"
echo ""

AMOUNTSHIELD=50000000000
AMOUNTTRANSFER=25000000000
AMOUNTUNSHIELD=15000000000

CLIENT="./substratee-client -p ${NPORT} -P ${RPORT}"

echo "* Query on-chain enclave registry:"
${CLIENT} list-workers
echo ""

if [ "$READMRENCLAVE" = "file" ]
then
    read MRENCLAVE <<< $(cat ~/mrenclave.b58)
    echo "Reading MRENCLAVE from file: ${MRENCLAVE}"
else
    # this will always take the first MRENCLAVE found in the registry !!
    read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
    echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"
fi
[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance "//Alice"
echo ""

echo "* Get balance of Bob's on-chain account"
${CLIENT} balance "//Bob"
echo ""

echo "* Create a new incognito account for Alice"
#ICGACCOUNTALICE=$(${CLIENT} trusted new-account --mrenclave ${MRENCLAVE})
ICGACCOUNTALICE=//AliceIncognito
echo "  Alice's incognito account = ${ICGACCOUNTALICE}"
echo ""

echo "* Create a new incognito account for Bob"
ICGACCOUNTBOB=$(${CLIENT} trusted new-account --mrenclave ${MRENCLAVE})
echo "  Bob's incognito account = ${ICGACCOUNTBOB}"
echo ""

# sometimes we get a nonce clash here, so let's wait a little bit to prevent that.
sleep 10

echo "* Shield ${AMOUNTSHIELD} tokens to Alice's incognito account"
${CLIENT} shield-funds //Alice ${ICGACCOUNTALICE} ${AMOUNTSHIELD} ${MRENCLAVE} ${WORKERPORT}
echo ""

echo "* Waiting 10 seconds"
sleep 10
echo ""

echo "Get balance of Alice's incognito account"
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

echo "Get balance of Alice's incognito account"
RESULT=$(${CLIENT} trusted balance ${ICGACCOUNTALICE} --mrenclave ${MRENCLAVE} | xargs)
echo $RESULT

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance "//Alice"
echo ""


# the following tests are for automated CI
# they only work if you're running from fresh genesis
case $TEST in
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