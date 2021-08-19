# integritee-worker

Integritee worker for Integritee [node](https://github.com/integritee-network/integritee-node) or [parachain](https://github.com/integritee-network/parachain)

This is part of [Integritee](https://integritee.network)

## Build and Run
Please see our [Integritee Book](https://book.integritee.network/howto_worker.html) to learn how to build and run this.

## Tests
### environment
Unit tests within the enclave can't be run by `cargo test`. All unit and integration tests can be run by the worker binary

first, you should run ipfs daemon because it is needed for testing
```
ipfs daemon
```
second, you'll need a integritee-node running
```
./target/release/integritee-node --dev --execution native
```
then you should make sure that the sealed_state is empty (but exists)
```
worker/bin$ rm sealed_stf_state.bin
worker/bin$ touch sealed_stf_state.bin
```

### execute tests
Run these with
```
integritee-service/bin$ ./integritee-service test_enclave --all
```

### End-to-end test with benchmarking

Including cleanup between runs:

run node
```
./target/release/integritee-node purge-chain --dev
./target/release/integritee-node --dev --ws-port 9979
```

run worker

```
export RUST_LOG=debug,substrate_api_client=warn,sp_io=warn,ws=warn,integritee_service=info,itc_enclave=info,sp_io::misc=debug,runtime=debug,itc_enclave::state=warn,ita_stf::sgx=info,light_client=warn,rustls=warn
rm -rf shards/ light_client_db.bin
./integritee-service -r 2002 -p 9979 -w 2001 run 2>&1 | tee worker.log
```

wait until you see the worker synching a few blocks. then check MRENCLAVE and update bot-community.py constants accordingly

```
./integritee-cli -p 9979 list-workers
```

now bootstrap a new bot community

```
./bot-community.py init
./bot-community.py benchmark
```

now you should see the community growing from 10 to hundreds, increasing with every ceremony
