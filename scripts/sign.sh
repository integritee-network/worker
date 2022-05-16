#!/bin/bash

bold=$(tput bold)
normal=$(tput sgr0)

if [ -z "$2" ]
then
  CONFIG=enclave.config.production.xml
else
  CONFIG=$2
fi

echo "The signing process of ${bold}$1${normal} started with config ${bold}$CONFIG${normal}"

sgx_sign gendata -enclave $1 -config $CONFIG -out enclave_sig.dat
openssl dgst -sha256 -sign intel_sgx.pem -out signature.dat enclave_sig.dat
openssl dgst -sha256 -verify intel_sgx.pub -signature signature.dat enclave_sig.dat
sgx_sign catsig -enclave $1 -config $CONFIG -out enclave.prod.signed.so -key intel_sgx.pub -sig signature.dat -unsigned enclave_sig.dat
sgx_sign dump -enclave enclave.prod.signed.so -cssfile sigstruct.bin -dumpfile metadata.info
grep mrsigner -A 2 metadata.info


echo "Signed enclave ${bold}enclave.prod.signed.so${normal} is ready to use"
