#!/usr/bin/env bash

cargo +nightly build --target wasm32-unknown-unknown --release

wasm-gc target/wasm32-unknown-unknown/release/substratee_worker_enclave_wasm.wasm target/wasm32-unknown-unknown/release/worker_enclave.compact.wasm
cp target/wasm32-unknown-unknown/release/worker_enclave.compact.wasm ../../bin