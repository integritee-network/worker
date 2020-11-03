#!/bin/bash

# M1 Demo
#
# bootstrap a bot currency on Encointer Cantillon Testnet

### first, start node
#   encointer-node-teeproxy --dev --ws-port 9979 -linfo,encointer=debug,runtime=debug
# 
### then, start worker
#   encointer-worker init-shard
#   encointer-worker signing-key
#   encointer-worker shielding-key
#   encointer-worker -p 9979 run
#
#  then run this script
#
### cleanup
# encointer-node-teeproxy purge-chain --dev
# bin/> rm -rf shards
# bin/> rm chain_relay_db.bin

# encointer-worker init-shard
## Cantillon node endpoint
#NURL=wss://cantillon.encointer.org
#NPORT=443
## Cantillon worker endpoint
#WURL=wss://substratee03.scs.ch
#WPORT=443

# local
NURL=ws://127.0.0.1
NPORT=9979
WURL=ws://127.0.0.1
WPORT=2000

CLIENT="./../bin/encointer-client-teeproxy -u $NURL -p $NPORT -U $WURL -P $WPORT"

echo "Using node address: $NURL:$NPORT"
echo "Using worker address: $WURL:$WPORT"
echo ""


#WORKERADDR="--worker-url ${WURL} --worker-port ${WPORT}"

# register new currency (with any funded on-chain account)
cid=$($CLIENT new-currency test-locations-sea-of-crete.json //Alice)
echo $cid

# list currenies
$CLIENT list-currencies

phase=$($CLIENT get-phase)
echo "phase is $phase"
if [ "$phase" == "REGISTERING" ]; then
   echo "that's fine"
elif [ "$phase" == "ASSIGNING" ]; then
   echo "need to advance"
   $CLIENT next-phase   
   $CLIENT next-phase
   echo "* Waiting 30 seconds such that phase change happened in enclave"
   sleep 30
elif [ "$phase" == "ATTESTING" ]; then
   echo "need to advance"
   $CLIENT next-phase   
   echo "* Waiting 30 seconds such that phase change happened in enclave"
  sleep 30
fi


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

timeout 10s $CLIENT trusted register-participant $account1 --mrenclave $MRENCLAVE --shard $cid
timeout 10s $CLIENT trusted register-participant $account2 --mrenclave $MRENCLAVE --shard $cid
timeout 10s $CLIENT trusted register-participant $account3 --mrenclave $MRENCLAVE --shard $cid

echo "*** registered participants"
sleep 30 # the above returns before TrustedCalls have been executed

# should be 1,2 and 3
$CLIENT trusted get-registration $account1 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted get-registration $account2 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted get-registration $account3 --mrenclave $MRENCLAVE --shard $cid 

$CLIENT next-phase
# should now be ASSIGNING

echo "* Waiting 30 seconds such that phase change happened in enclave"
sleep 30
echo ""

$CLIENT trusted info --mrenclave $MRENCLAVE --shard $cid

$CLIENT next-phase
# should now be ATTESTING

echo "* Waiting 30 seconds such that phase change happened in enclave"
sleep 30
echo ""

echo "*** start meetup"
claim1=$($CLIENT trusted new-claim $account1 3 --mrenclave $MRENCLAVE --shard $cid )
claim2=$($CLIENT trusted new-claim $account2 3 --mrenclave $MRENCLAVE --shard $cid )
claim3=$($CLIENT trusted new-claim $account3 3 --mrenclave $MRENCLAVE --shard $cid )

echo "Claim1 = ${claim1}"
echo "Claim2 = ${claim2}"
echo "Claim3 = ${claim3}"

echo "*** sign each others claims"
witness1_2=$($CLIENT trusted sign-claim $account1 $claim2 --mrenclave $MRENCLAVE --shard $cid)
witness1_3=$($CLIENT trusted sign-claim $account1 $claim3 --mrenclave $MRENCLAVE --shard $cid)

witness2_1=$($CLIENT trusted sign-claim $account2 $claim1 --mrenclave $MRENCLAVE --shard $cid)
witness2_3=$($CLIENT trusted sign-claim $account2 $claim3 --mrenclave $MRENCLAVE --shard $cid)

witness3_1=$($CLIENT trusted sign-claim $account3 $claim1 --mrenclave $MRENCLAVE --shard $cid)
witness3_2=$($CLIENT trusted sign-claim $account3 $claim2 --mrenclave $MRENCLAVE --shard $cid)

echo "*** send witnesses to chain"
$CLIENT trusted register-attestations $account1 $witness2_1 $witness3_1 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted register-attestations $account2 $witness1_2 $witness3_2 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted register-attestations $account3 $witness1_3 $witness2_3 --mrenclave $MRENCLAVE --shard $cid 


$CLIENT trusted get-attestations $account1 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted get-attestations $account2 --mrenclave $MRENCLAVE --shard $cid 
$CLIENT trusted get-attestations $account3 --mrenclave $MRENCLAVE --shard $cid 

$CLIENT next-phase
# should now be REGISTERING

echo "* Waiting 30 seconds such that phase change happened in enclave"
sleep 30
echo ""

echo "account balances for new currency with cid $cid"
$CLIENT trusted balance $account1 --mrenclave $MRENCLAVE --shard $cid
$CLIENT trusted balance $account2 --mrenclave $MRENCLAVE --shard $cid
$CLIENT trusted balance $account3 --mrenclave $MRENCLAVE --shard $cid
echo "currency info (publicly readable)"
$CLIENT trusted info --mrenclave $MRENCLAVE --shard $cid