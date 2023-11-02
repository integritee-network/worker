#!/bin/bash
set -e

# Check if the first argument is "mrenclave"
if [ "$1" = "mrenclave" ]; then
    # If "mrenclave" is provided, execute the corresponding command
    $SGX_ENCLAVE_SIGNER dump \
      -enclave /usr/local/bin/enclave.signed.so \
      -dumpfile df.out && \
        /usr/local/bin/extract_identity < df.out && rm df.out | grep -oP ':\s*\K[a-fA-F0-9]+'
elif [ "$1" = "cargo-test" ]; then
    echo "Running cargo test"
    # Remove the first argument (which is 'cargo-test')
    shift
    # Pass all the remaining arguments to the 'cargo test' command
    cargo test "$@"
else
    # If no specific command is provided, execute the default unnamed command

    # run aesmd in the background
    /opt/intel/sgx-aesm-service/aesm/aesm_service

    exec /usr/local/bin/integritee-service "${@}"
fi