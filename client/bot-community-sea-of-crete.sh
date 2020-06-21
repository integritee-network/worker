#!/bin/bash

# this script should be called once per ceremony phase in order to maintain a constant population
# on Cantillon it is sufficient to call it once per day with cron
#
# as a normal user, run 
# > crontab -e
#
# and add one line:
# 0 8 * * * timeout 600s /home/cantillon/bin/bot-community-sea-of-crete.sh >> /home/cantillon/bin/bot-community-sea-of-crete.log 2>&1
#
# because of issue #11 the client can hang if calls fail and we need to timeout the script
#

date

# Cantillon node endpoint
NURL=wss://cantillon.encointer.org
NPORT=443
# Cantillon worker endpoint
WURL=wss://substratee03.scs.ch
WPORT=443

nctr="/home/cantillon/bin/encointer-client -u $NURL -p $NPORT -U $WURL -P $WPORT"
cd /home/cantillon/bin

phase=$($nctr get-phase)
echo $phase

MRENCLAVE=J9D51UiwXnNbG1e76q7MivWmA944JdWXvsTUpM2HREta
cid=7eLSZLSMShw4ju9GvuMmoVgeZxZimtvsGTSvLEdvcRqQ

accounts=(//AliceIncognito \
//BobIncognito \
//CharlieIncognito)

echo "as Alice will pay for all proxy fees, check her balance"
$nctr balance //Alice

if [ $phase = "REGISTERING" ]; then
  for p in ${accounts[@]}; do
    $nctr trusted balance $p --mrenclave $MRENCLAVE --shard $cid
    $nctr trusted register-participant $p --mrenclave $MRENCLAVE --shard $cid
  done

  sleep 60

  echo "verify registrations:"

  for p in ${accounts[@]}; do
    $nctr trusted get-registration $p --mrenclave $MRENCLAVE --shard $cid
  done

fi

if [ $phase = "ASSIGNING" ]; then
  echo "verify meetup assignments NOT YET SUPPORTED BY CLIENT"
fi

if [ $phase = "ATTESTING" ]; then
  echo "performing bot meetup. as we can't look up meetup assignments, we assume everybody got assigned to the same meetup"
  N=${#accounts[@]}
  echo "number of participants is $N"
  claims=()
  for ((i = 0; i < $N; i++)); do
    #claim="claim-for-${m[i]}-vote-$N" # 
    claim=""
    # queries can fail (see worker #12). just try again
    while [ -z "$claim" ]; do
      claim=$($nctr trusted new-claim ${accounts[i]} $N --mrenclave $MRENCLAVE --shard $cid)
      sleep 1
    done
    echo "CLAIM: $claim"
    claims+=( $claim )
  done
  for ((i = 0; i < $N; i++)); do
    attestations=()
    for ((j = 0; j < $N; j++)); do
      if [[ $i -eq $j ]]; then continue; fi
      echo "${accounts[$j]} attests:${claims[$i]}"
      attestation=$($nctr sign-claim ${accounts[$j]} ${claims[$i]})
      echo "ATTESTATION: $attestation"
      attestations+=( $attestation )
    done
    echo "register attestations for ${accounts[$i]}"
    echo "command: $nctr trusted register-attestations ${accounts[$i]} ${attestations[@]} --mrenclave $MRENCLAVE --shard $cid"
    $nctr trusted register-attestations ${accounts[$i]} ${attestations[@]} --mrenclave $MRENCLAVE --shard $cid
  done
fi

