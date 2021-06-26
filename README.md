# integritee-worker

Integritee worker for Integritee [node](https://github.com/integritee-network/integritee-node) or [parachain](https://github.com/integritee-network/parachain)

This is part of [Integritee](https://integritee.network)

SubstraTEE is in the process of rebranding to Integritee. In the following, please treat the two as synonyms

## Build and Run
Please see our [SubstraTEE Book](https://www.substratee.com/howto_worker.html) to learn how to build and run this.

## Tests
### environment
Unit tests within the enclave can't be run by `cargo test`. All unit and integration tests can be run by the worker binary

first, you should run ipfs daemon because it is needed for testing
```
ipfs daemon
```
second, you'll need a substraTEE-node running
```
./target/release/substratee-node --dev --execution native
```
then you should make sure that the sealed_state is empty (but exists)
```
substraTEE-worker/bin$ rm sealed_stf_state.bin
substraTEE-worker/bin$ touch sealed_stf_state.bin
```

### execute tests
Run these with
```
substraTEE-worker/bin$ ./substratee-worker test_enclave --all
```

### End-to-end test with benchmarking

Including cleanup between runs:

run node
```
./target/release/substratee-node purge-chain --dev
./target/release/substratee-node --dev --ws-port 9979
```

run worker

```
export RUST_LOG=debug,substrate_api_client=warn,sp_io=warn,ws=warn,substratee_worker=info,substratee_worker_enclave=info,sp_io::misc=debug,runtime=debug,substratee_worker_enclave::state=warn,substratee_stf::sgx=info,chain_relay=warn,rustls=warn
rm -rf shards/ chain_relay_db.bin
./substratee-worker -r 2002 -p 9979 -w 2001 run 2>&1 | tee worker.log
```

wait until you see the worker synching a few blocks. then check MRENCLAVE and update bot-community.py constants accordingly

```
./substratee-client -p 9979 list-workers
```

now bootstrap a new bot community

```
./bot-community.py init
./bot-community.py benchmark
```

now you should see the community growing from 10 to hundreds, increasing with every ceremony
