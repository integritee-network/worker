#!/bin/bash

# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --tmp --dev -lruntime=debug
#   rm light_client_db.bin
#   integritee-service init_shard
#   integritee-service shielding-key
#   integritee-service signing-key
#   export RUST_LOG=integritee_service=info,ita_stf=debug
#   integritee-service run
#
# then run this script

# usage:
#  demo_rps.sh -p <NODEPORT> -P <WORKERPORT> -m file
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

CLIENT="./../bin/integritee-cli -p ${NPORT} -P ${RPORT}"

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

echo "Alice (sudo) sets initial balances"
${CLIENT} trusted set-balance //Alice 1000 --mrenclave ${MRENCLAVE} --direct
${CLIENT} trusted set-balance //Bob 1000 --mrenclave ${MRENCLAVE} --direct
echo ""


echo "Alice starts new game against Bob"
${CLIENT} trusted new-game //Alice //Bob --mrenclave ${MRENCLAVE} --direct
echo ""

echo "Alice chooses her weapon"
${CLIENT} trusted choose //Alice Rock --mrenclave ${MRENCLAVE} --direct
echo ""

echo "Bob chooses his weapon"
${CLIENT} trusted choose //Bob Paper --mrenclave ${MRENCLAVE} --direct
echo ""

echo "Alice reveals"
${CLIENT} trusted reveal //Alice Rock --mrenclave ${MRENCLAVE} --direct
echo ""

echo "Bob reveals"
${CLIENT} trusted reveal //Bob Paper --mrenclave ${MRENCLAVE} --direct
echo ""

echo "Query result"
${CLIENT} trusted get-game //Bob --mrenclave ${MRENCLAVE} --direct
echo ""

exit 0
