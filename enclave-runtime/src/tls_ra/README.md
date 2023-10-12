# provisioning 

each worker runs a provisioning server for other workers of the same MRENCLAVE and shard to get recent stf state and secrets from.

Light client storage can also be provisioned to avoid re-synching the entire parentchains with each worker

```mermaid
sequenceDiagram
participant server
participant client
server ->> server: generate shielding & state encryption key
server ->> server: init_shard & sync parentchains
client ->> server: enclave_request_state_provisioning
activate client
client ->> client: qe_get_target_info



deactivate client


```
