#!/usr/bin/env bash

cargo +nightly build --target wasm32-unknown-unknown --release
wasm-gc target/wasm32-unknown-unknown/release/wasm_runtime.wasm target/wasm32-unknown-unknown/release/wasm_runtime.compact.wasm

cp target/wasm32-unknown-unknown/release/wasm_runtime.compact.wasm ../bin