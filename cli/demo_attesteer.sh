#!/bin/bash

while getopts ":a:m:p:P:t:u:V:C:" opt; do
    case $opt in
        p)
            NPORT=$OPTARG
            ;;
        P)
            WORKER1PORT=$OPTARG
            ;;
        u)
            NODEURL=$OPTARG
            ;;
        C)
            CLIENT_BIN=$OPTARG
            ;;
        V)
            WORKER1URL=$OPTARG
            ;;
        # hex encoded attestation filename
        # Generate it with
        # xxd -plain quote.dat | tr -d '[[:blank:][:space:]]' > quote_single_line.hex
        a)
            REMOTE_ATTESTATION=$OPTARG
            ;;
        # attestation type "ias" vs "dcap"
        t)
            TYPE=$OPTARG
            ;;
    esac
done

echo "rem at is: ${REMOTE_ATTESTATION}, TYPE is: ${TYPE}"

# instantiate client as usual
CLIENT="${CLIENT_BIN} -p ${NPORT} -P ${WORKER1PORT} -u ${NODEURL} -U ${WORKER1URL}"

# attestation command
ATTESTEER_CMD="attesteer send-${TYPE}-attestation-report"

# call attesteer api
RESULT=`${CLIENT} ${ATTESTEER_CMD} ${ATTESTATION}`

# assert result (this needs to be tweaked a bit to support both attestation types.
IF ${RESULT} = `IAS attestation report verification succeded.`
   exit 0
ELSE
   exit 1