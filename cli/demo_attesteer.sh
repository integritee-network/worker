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
ATTESTEER_CMD="attesteer"
case ${TYPE} in
    ias|IAS)
        ATTESTEER_CMD+="send-ias-attestation-report"
    ;;
    dcap|DCAP)
        ATTESTEER_CMD+="send-dcap-quote"
    ;;

esac

ATTESTEER_CMD+=${REMOTE_ATTESTATION}


# call attesteer api
RESULT=`${CLIENT} ${ATTESTEER_CMD} ${ATTESTATION}`

# assert result (this needs to be tweaked a bit to support both attestation types.
case ${RESULT} in 
    "DCAP quote verification succeded.")
        exit 0
    ;;
    "IAS attestation report verification succeded.")
        exit 0
    ;;
    *)
        echo "attestation verification failed with: ${RESULT}"
        exit 1
    ;;
esac