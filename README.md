# substraTEE-worker

![badge](https://img.shields.io/badge/substrate-2.0.0--alpha.7-success)

SubstraTEE worker for SubstraTEE node

This is part of [substraTEE](https://github.com/scs/substraTEE)

## Development environment
**Supports Rust nightly-2020-04-07**

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
