#!/bin/bash
set -e

# Check if the first argument is "mrenclave"
if [ "$1" = "mrenclave" ]; then
    # If "mrenclave" is provided, execute the corresponding command
    $SGX_ENCLAVE_SIGNER dump \
      -enclave /usr/local/bin/enclave.signed.so \
      -dumpfile df.out && \
        /usr/local/bin/extract_identity < df.out && rm df.out | grep -o -E '[0-9a-fA-F]{64}'

else
    # If no specific command is provided, execute the default unnamed command

    # run aesmd in the background
    /opt/intel/sgx-aesm-service/aesm/aesm_service

    exec /usr/local/bin/integritee-service "${@}"
fi