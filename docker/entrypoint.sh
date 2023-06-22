#!/bin/bash
set -e

# run aesmd in the background
/opt/intel/sgx-aesm-service/aesm/aesm_service

exec /usr/local/bin/integritee-service "${@}"
