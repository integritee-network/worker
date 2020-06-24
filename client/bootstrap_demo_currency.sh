#!/bin/bash

# M1 Demo
#
# bootstrap a bot currency on Encointer Cantillon Testnet

## Cantillon node endpoint
#NURL=wss://cantillon.encointer.org
#NPORT=443
## Cantillon worker endpoint
#WURL=wss://substratee03.scs.ch
#WPORT=443

# locals
NURL=ws://127.0.0.1
NPORT=9979
WURL=ws://127.0.0.1
WPORT=2000

CLIENT="./../bin/encointer-client-teeproxy -u $NURL -p $NPORT -U $WURL -P $WPORT"

wait_for_phase() {
  current_phase=$($CLIENT get-phase)

  echo "waiting for phase: $1 ..."

  while  [ "$current_phase" != "$1" ]; do
    echo "current phase: $current_phase ... waiting for phase $1"
    sleep 10
    current_phase=$($CLIENT get-phase)
  done

  echo "current_phase is $1, progress script"
}

echo "Using node address: $NURL:$NPORT"
echo "Using worker address: $WURL:$WPORT"
echo ""


#WORKERADDR="--worker-url ${WURL} --worker-port ${WPORT}"

# register new currency (with any funded on-chain account)
cid=$($CLIENT new-currency test-locations-sea-of-crete.json //Alice)
echo $cid

# list currenies
$CLIENT list-currencies

wait_for_phase REGISTERING

read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2 }')
#cid=7eLSZLSMShw4ju9GvuMmoVgeZxZimtvsGTSvLEdvcRqQ
#MRENCLAVE=6AkpQeSLGSwESvKMiygJzDTLHXvnwBG9c8Q8FV9LiDuN

echo "  MRENCLAVE = ${MRENCLAVE}"

# new account with
# $CLIENT trusted new-account --mrenclave $MRENCLAVE --shard $cid

# these must be registered bootstrappers
account1=//AliceIncognito
account2=//BobIncognito
account3=//CharlieIncognito

$CLIENT trusted get-registration $account1 --mrenclave $MRENCLAVE --shard $cid
# should be zero

$CLIENT trusted register-participant $account1 --mrenclave $MRENCLAVE --shard $cid
$CLIENT trusted register-participant $account2 --mrenclave $MRENCLAVE --shard $cid
$CLIENT trusted register-participant $account3 --mrenclave $MRENCLAVE --shard $cid

echo "*** registered participants"
sleep 10 # the above returns before TrustedCalls have been executed

# should be 1,2 and 3
$CLIENT trusted get-registration $account1 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted get-registration $account2 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted get-registration $account3 --mrenclave $MRENCLAVE --shard $cid 

wait_for_phase ASSIGNING

# nothing to do here until we can have debug getters

wait_for_phase ATTESTING

echo "* Waiting 5 seconds such that phase change happened in enclave"
sleep 5
echo ""

echo "*** start meetup"
claim1=$($CLIENT trusted new-claim $account1 3 --mrenclave $MRENCLAVE --shard $cid )
claim2=$($CLIENT trusted new-claim $account2 3 --mrenclave $MRENCLAVE --shard $cid )
claim3=$($CLIENT trusted new-claim $account3 3 --mrenclave $MRENCLAVE --shard $cid )

echo "Claim1 = ${claim1}"
echo "Claim2 = ${claim2}"
echo "Claim3 = ${claim3}"

echo "*** sign each others claims"
witness1_2=$($CLIENT sign-claim $account1 $claim2)
witness1_3=$($CLIENT sign-claim $account1 $claim3)

witness2_1=$($CLIENT sign-claim $account2 $claim1)
witness2_3=$($CLIENT sign-claim $account2 $claim3)

witness3_1=$($CLIENT sign-claim $account3 $claim1)
witness3_2=$($CLIENT sign-claim $account3 $claim2)

echo "*** send witnesses to chain"
$CLIENT trusted register-attestations $account1 $witness2_1 $witness3_1 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted register-attestations $account2 $witness1_2 $witness3_2 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted register-attestations $account3 $witness1_3 $witness2_3 --mrenclave $MRENCLAVE --shard $cid 


$CLIENT trusted get-attestations $account1 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted get-attestations $account2 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted get-attestations $account3 --mrenclave $MRENCLAVE --shard $cid 

wait_for_phase REGISTERING

echo "* Waiting 5 seconds such that phase change happened in enclave"
sleep 5
echo ""

echo "account balances for new currency with cid $cid"
$CLIENT trusted balance $account1 --mrenclave $MRENCLAVE --shard $cid
$CLIENT trusted balance $account2 --mrenclave $MRENCLAVE --shard $cid
$CLIENT trusted balance $account3 --mrenclave $MRENCLAVE --shard $cid
echo "total issuance (publicly readable)"
$CLIENT trusted total-issuance --mrenclave $MRENCLAVE --shard $cid
