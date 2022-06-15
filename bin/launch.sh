rm light_client_db.bin*
rm -r shards
rm -r sidechain_db
#export RUST_LOG=debug,ws=warn,sp_io=warn,substrate_api_client=warn,jsonrpsee_ws_client=warn,jsonrpsee_ws_server=warn,enclave_runtime=warn,integritee_service=warn,itc_tls_websocket_server=error
./integritee-service init-shard
./integritee-service shielding-key
./integritee-service signing-key
./integritee-service --ws-external run --dev --skip-ra
