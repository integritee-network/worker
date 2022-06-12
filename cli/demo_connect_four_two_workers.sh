#!/bin/bash

# setup:
# build ajuna node with skip-ias-check on branch "validateer-setup"
#   cargo build --release --features solo,skip-ias-check
#
# run ajuna node
#   ./target/release/ajuna-solo  --dev --tmp --ws-port <NODEPORT>
#
# run worker inside the bin folder:
#   rm light_client_db.bin
#   rm -r shards
#   rm -r sidechain_db
#   export RUST_LOG=integritee_service=info,ita_stf=debug
#   ./integritee-service init-shard
#   ./integritee-service shielding-key
#   ./integritee-service signing-key
#   ./integritee-service -P <WORKERPORT> -p <NODEPORT> -r <REMOTE-ATTESTATION-PORT> run --dev --skip-ra
#
# then run this script

# usage:
#  export RUST_LOG=integritee-cli=info,ita_stf=info
#  demo_connect_four.sh -p <NODEPORT> -A <WORKER1PORT> -B <WORKER2PORT> -m file
#
# if -m file is set, the mrenclave will be read from file  ~/mrenclave.b58

while getopts ":m:p:A:B:" opt; do
    case $opt in
        m)
            READMRENCLAVE=$OPTARG
            ;;
        p)
            NPORT=$OPTARG
            ;;
        A)
            WORKER1PORT=$OPTARG
            ;;
        B)
            WORKER2PORT=$OPTARG
            ;;
    esac
done

# using default port if none given as arguments
NPORT=${NPORT:-9944}
WORKER1PORT=${WORKER1PORT:-2000}
WORKER2PORT=${WORKER2PORT:-3000}

echo "Using node-port ${NPORT}"
echo "Using trusted-worker-1-port ${WORKER1PORT}"
echo "Using trusted-worker-2-port ${WORKER2PORT}"

BALANCE=1000

CLIENTWORKER1="./../bin/integritee-cli -p ${NPORT} -P ${WORKER1PORT}"
CLIENTWORKER2="./../bin/integritee-cli -p ${NPORT} -P ${WORKER2PORT}"

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

echo ""
echo "* Create account for Alice"
ACCOUNTALICE=//Alice
echo "  Alice's account = ${ACCOUNTALICE}"
echo ""

echo "* Create account for Bob"
ACCOUNTBOB=//Bob
echo "  Bob's account = ${ACCOUNTBOB}"
echo ""

echo "* Issue ${BALANCE} tokens to Alice's account via Worker 1"
${CLIENTWORKER1} trusted  --mrenclave=${MRENCLAVE} --direct set-balance ${ACCOUNTALICE} ${BALANCE}
echo ""
sleep 1

echo "* Issue ${BALANCE} tokens to Bob's account via Worker 2"
${CLIENTWORKER2} trusted  --mrenclave=${MRENCLAVE} --direct set-balance ${ACCOUNTBOB} ${BALANCE}
echo ""
sleep 1

echo "Queue Game for Alice (Player 1)"
${CLIENTWORKER1} queue-game ${ACCOUNTALICE}
echo ""
sleep 1

echo "Queue Game for Bob (Player 2)"
${CLIENTWORKER2} queue-game ${ACCOUNTBOB}
echo ""
sleep 1

echo "waiting"
sleep 45

echo "Turn for Alice (Player 1 via Worker 1)"
${CLIENTWORKER1} trusted  --direct --mrenclave=${MRENCLAVE} play-turn ${ACCOUNTALICE} 3
echo ""
sleep 1

echo "Turn for Bob (Player 2 via Worker 2)"
${CLIENTWORKER2} trusted  --direct --mrenclave=${MRENCLAVE} play-turn ${ACCOUNTBOB} 4
sleep 1

echo "Turn for Alice (Player 1 via Worker 1)"
${CLIENTWORKER1} trusted  --direct --mrenclave=${MRENCLAVE} play-turn ${ACCOUNTALICE} 2
echo ""
sleep 1

echo "Turn for Bob (Player 2 via Worker 2)"
${CLIENTWORKER2} trusted  --direct --mrenclave=${MRENCLAVE} play-turn ${ACCOUNTBOB} 3
echo ""
sleep 1

echo "waiting"
sleep 5

echo "Board after 2 turns (queried by Bob via Worker 2)"
${CLIENTWORKER2} trusted --direct --mrenclave=${MRENCLAVE} get-board ${ACCOUNTBOB}
echo ""
sleep 1


echo "Turn for Alice (Player 1 via Worker 1)"
${CLIENTWORKER1} trusted --direct --mrenclave=${MRENCLAVE} play-turn ${ACCOUNTALICE} 2
sleep 1

echo "Turn for Bob (Player 2 via Worker 2)"
${CLIENTWORKER2} trusted --direct --mrenclave=${MRENCLAVE} play-turn ${ACCOUNTBOB} 5
echo ""
sleep 1

echo "Turn for Alice (Player 1 via Worker 1)"
${CLIENTWORKER1} trusted --direct --mrenclave=${MRENCLAVE} play-turn ${ACCOUNTALICE} 2
echo ""
sleep 1

echo "Turn for Bob (Player 2 via Worker 2)"
${CLIENTWORKER2} trusted --direct --mrenclave=${MRENCLAVE} play-turn ${ACCOUNTBOB} 1
echo ""
sleep 1

echo "waiting"
sleep 5

echo "Board after 4 turns (queried by Alice via Worker 1)"
${CLIENTWORKER1} trusted --direct --mrenclave=${MRENCLAVE} get-board ${ACCOUNTALICE}
echo ""
sleep 1

echo "Turn for Alice  (Player 1 via Worker 1)"
${CLIENTWORKER1} trusted --direct --mrenclave=${MRENCLAVE} play-turn ${ACCOUNTALICE} 2
echo ""
sleep 1

echo "waiting"
sleep 5

echo "Board after end of game (queried by Alice via Worker 1)"
${CLIENTWORKER2} trusted --direct --mrenclave=${MRENCLAVE} get-board ${ACCOUNTBOB}
echo ""
