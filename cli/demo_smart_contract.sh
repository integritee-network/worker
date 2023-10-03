#!/bin/bash

# Deploys a simple counter smart contract on our EVM sidechain and increments the value.
#
# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --tmp --dev -lruntime=debug
#   export RUST_LOG=integritee_service=info,ita_stf=debug
#   integritee-service run
#
# then run this script

# usage:
#  export RUST_LOG_LOG=integritee-cli=info,ita_stf=info
#  demo_smart_contract.sh -p <NODEPORT> -P <WORKER_PORT>

while getopts ":p:A:u:V:C:" opt; do
    case $opt in
        p)
            INTEGRITEE_RPC_PORT=$OPTARG
            ;;
        A)
            WORKER_PORT=$OPTARG
            ;;
        u)
            INTEGRITEE_RPC_URL=$OPTARG
            ;;
        V)
            WORKER_URL=$OPTARG
            ;;
        C)
            CLIENT_BIN=$OPTARG
            ;;
        *)
            echo "invalid arg ${OPTARG}"
            exit 1
    esac
done

#  Bytecode from Counter.sol with slightly modified values
SMARTCONTRACT="608060405234801561001057600080fd5b50602260008190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610378806100696000396000f3fe6080604052600436106100435760003560e01c80631003e2d21461004e57806333cf508014610077578063371303c0146100a257806358992216146100b957610044565b5b6042600081905550005b34801561005a57600080fd5b50610075600480360381019061007091906101e4565b6100e4565b005b34801561008357600080fd5b5061008c610140565b604051610099919061024a565b60405180910390f35b3480156100ae57600080fd5b506100b7610149565b005b3480156100c557600080fd5b506100ce6101a5565b6040516100db919061022f565b60405180910390f35b806000808282546100f59190610265565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008054905090565b600160008082825461015b9190610265565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b6000813590506101de8161032b565b92915050565b6000602082840312156101fa576101f9610326565b5b6000610208848285016101cf565b91505092915050565b61021a816102bb565b82525050565b610229816102ed565b82525050565b60006020820190506102446000830184610211565b92915050565b600060208201905061025f6000830184610220565b92915050565b6000610270826102ed565b915061027b836102ed565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156102b0576102af6102f7565b5b828201905092915050565b60006102c6826102cd565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600080fd5b610334816102ed565b811461033f57600080fd5b5056fea26469706673582212206242c58933a5e80fcfdd7f0044569af44caa21c61740067483a287cc361fc5b464736f6c63430008070033"
INCFUNTION="371303c0"
DEFAULTFUNCTION="371303c1"
ADDFUNCTION="1003e2d20000000000000000000000000000000000000000000000000000000000000003"


# using default port if none given as arguments
INTEGRITEE_RPC_PORT=${INTEGRITEE_RPC_PORT:-9944}
INTEGRITEE_RPC_URL=${INTEGRITEE_RPC_URL:-"ws://127.0.0.1"}

WORKER_PORT=${WORKER_PORT:-2000}
WORKER_URL=${WORKER_URL:-"wss://127.0.0.1"}


CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

echo "Using client binary ${CLIENT_BIN}"
${CLIENT_BIN} --version
echo "Using node uri ${INTEGRITEE_RPC_URL}:${INTEGRITEE_RPC_PORT}"
echo "Using trusted-worker uri ${WORKER_URL}:${WORKER_PORT}"

CLIENTWORKER="${CLIENT_BIN} -p ${INTEGRITEE_RPC_PORT} -P ${WORKER_PORT} -u ${INTEGRITEE_RPC_URL} -U ${WORKER_URL}"


# this will always take the first MRENCLAVE found in the registry !!
read -r MRENCLAVE <<< "$($CLIENTWORKER list-workers | awk '/  MRENCLAVE: / { print $2; exit }')"
echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"

ACCOUNTALICE=//Alice

echo "Create smart contract"
${CLIENTWORKER} trusted --mrenclave ${MRENCLAVE} --direct evm-create ${ACCOUNTALICE} ${SMARTCONTRACT}
echo ""

echo "Get storage"
${CLIENTWORKER} trusted --mrenclave ${MRENCLAVE} evm-read ${ACCOUNTALICE} 0x8a50db1e0f9452cfd91be8dc004ceb11cb08832f
echo ""

echo "Call inc function"
${CLIENTWORKER} trusted --mrenclave ${MRENCLAVE} --direct evm-call ${ACCOUNTALICE} 0x8a50db1e0f9452cfd91be8dc004ceb11cb08832f ${INCFUNTION}
echo ""

echo "Get storage"
${CLIENTWORKER} trusted --mrenclave ${MRENCLAVE} evm-read ${ACCOUNTALICE} 0x8a50db1e0f9452cfd91be8dc004ceb11cb08832f
echo ""

echo "Call add 3 function"
${CLIENTWORKER} trusted --mrenclave ${MRENCLAVE} --direct evm-call ${ACCOUNTALICE} 0x8a50db1e0f9452cfd91be8dc004ceb11cb08832f ${ADDFUNCTION}
echo ""

echo "Get storage"
RESULT=$(${CLIENTWORKER} trusted --mrenclave ${MRENCLAVE} evm-read ${ACCOUNTALICE} 0x8a50db1e0f9452cfd91be8dc004ceb11cb08832f | xargs)
echo $RESULT
echo ""

EXPECTED_RETURN_VALUE="0x0000000000000000000000000000000000000000000000000000000000000026"

echo "* Verifying correct return value"
if (("$RESULT" == "$EXPECTED_RETURN_VALUE")); then
    echo "Smart contract return value is correct ($RESULT)"
    exit 0
else
    echo "Smart contract return value is wrong (expected: $EXPECTED_RETURN_VALUE, actual: $RESULT)"
    exit 1
fi

exit 0
