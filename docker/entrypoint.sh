#!/bin/bash
set -e

# run aesmd in the background
/opt/intel/sgx-aesm-service/aesm/aesm_service

# for debugging: will be in the CI logs:
cat /etc/sgx_default_qcnl.conf

echo '{
  
  "pccs_url": "https://ajuna-02.cluster.securitee.tech:8081/sgx/certification/v4/",

  "use_secure_cert": false,

  "collateral_service": "https://api.trustedservices.intel.com/sgx/certification/v4/",


  "retry_times": 6,

  "retry_delay": 10,


  "pck_cache_expire_hours": 168,

  "verify_collateral_cache_expire_hours": 168

}' > /etc/sgx_default_qcnl.conf

cat /etc/sgx_default_qcnl.conf

exec /usr/local/bin/integritee-service "${@}"
