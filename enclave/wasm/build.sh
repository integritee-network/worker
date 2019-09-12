#!/usr/bin/env bash

if [[ "${SGX_DEBUG}" == 0 ]]; then
    BUILD_TARGET="--release"
    OUTPUT_PATH="release"
else
    BUILD_TARGET=""
    OUTPUT_PATH="debug"
fi

cargo build --target wasm32-unknown-unknown ${BUILD_TARGET}

wasm-gc ../target/wasm32-unknown-unknown/${OUTPUT_PATH}/substratee_worker_enclave_wasm.wasm ../target/wasm32-unknown-unknown/${OUTPUT_PATH}/worker_enclave.compact.wasm
cp ../target/wasm32-unknown-unknown/${OUTPUT_PATH}/worker_enclave.compact.wasm ../../bin
