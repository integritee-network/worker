#!/bin/bash

# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --dev -lruntime=debug
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
echo "Using trusted-worker-port ${RPORT}"
echo ""

CLIENT="./../bin/integritee-cli -p ${NPORT} -P ${RPORT}"

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
ALICE_ONCHAIN_BALANCE = $(${CLIENT} balance "//Alice" | xargs )
echo $ALICE_ONCHAIN_BALANCE
echo ""
echo "Multiplying Alice Balance by ten:"
MORE_THAN_ALICE_BALANCE = $(expr ${ALICE_ONCHAIN_BALANCE} \* 10)
echo $MORE_THAN_ALICE_BALANCE
echo ""

echo "* Create a new incognito account for Alice"
ICGACCOUNTALICE=//AliceIncognito
echo "  Alice's incognito account = ${ICGACCOUNTALICE}"
echo ""

echo "* Shield ${MORE_THAN_ALICE_BALANCE} tokens to Alice's incognito account"
${CLIENT} shield-funds //Alice ${ICGACCOUNTALICE} ${MORE_THAN_ALICE_BALANCE} ${MRENCLAVE} ${WORKERPORT}
echo ""

echo "* Waiting 10 seconds"
sleep 10
echo ""

echo "Get balance of Alice's incognito account"
${CLIENT} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTALICE}
echo ""


echo "Get balance of Alice's incognito account"
ALICE_OFFCHAIN_BALANCE=$(${CLIENT} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTALICE}  | xargs)
echo $ALICE_OFFCHAIN_BALANCE
echo ""

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance "//Alice"
echo ""


# the following tests are for automated CI
# they only work if you're running from fresh genesis
case $TEST in
    first)
        if [ "$MORE_THAN_ALICE_BALANCE" = "$ALICE_OFFCHAIN_BALANCE" ]; then
            echo "Something is definitely wrong here.."
            exit 1
        else
            echo "test ran through but balance is wrong. have you run the script from fresh genesis?"
            exit 1
        fi
        ;;
esac

exit 0
