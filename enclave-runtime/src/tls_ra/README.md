# provisioning 

each worker runs a provisioning server for other workers of the same MRENCLAVE and shard to get recent stf state and secrets from.

Light client storage can also be provisioned to avoid re-synching the entire parentchains with each worker

enclave instances are short-lived on both sides, just for a single request.

```mermaid
sequenceDiagram
participant untrusted_server
participant enclave_server
participant enclave_client
participant untrusted_client
enclave_server ->> enclave_server: generate shielding & state encryption key
enclave_server ->> enclave_server: init_shard & sync parentchains
untrusted_client ->> untrusted_server: connect TCP
untrusted_client ->> enclave_client: request_state_provisioning
activate enclave_client
untrusted_server ->> enclave_server: run_state_provisioning_server
activate enclave_server
enclave_server ->> enclave_server: load state and secrets 
enclave_client ->> enclave_server: open TLS session (including MU RA)
enclave_client ->> enclave_server: request_state_provisioning(shard, account)
enclave_server ->> enclave_client: write_provisioning_payloads
enclave_server ->> enclave_server: add client as vault proxy for shard
enclave_client ->> enclave_client: seal state and secrets to disk
enclave_client -->> untrusted_client: _
deactivate enclave_client
enclave_server -->> untrusted_server: _
deactivate enclave_server
untrusted_client --> untrusted_server: disconnect TCP
```
