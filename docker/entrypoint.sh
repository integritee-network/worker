#!/bin/bash
set -e

# run aesmd in the background
/opt/intel/sgx-aesm-service/aesm/aesm_service

# for debugging: will be in the CI logs:
cat /etc/sgx_default_qcnl.conf

exec /usr/local/bin/integritee-service "${@}"
