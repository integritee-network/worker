# simplyR

A Rust implementation of the BEST matching algorithm.

[![CI](https://github.com/BESTenergytrade/simplyR/actions/workflows/ci.yml/badge.svg)](https://github.com/BESTenergytrade/simplyR/actions/workflows/ci.yml)

## Installation

* For Ubuntu 20.04 and higher, you need to install some dependencies:

```sh
sudo apt install git build-essential
```

* Install the latest stable version of Rust (at least version 1.66.0), e.g. via <https://rustup.rs/>

* Get the code

```sh
git clone ...
cd simplyR
```

* Compile, run

```sh
# Build and run
cargo run
# Build and run in release mode
cargo run --release
# Build only
cargo build
# Build in release mode (slower build, but faster runtime)
cargo build --release
```

The binary is located in the `target` directory:

* `target/release/simplyr` for release builds
* `target/debug/simplyr` for debug builds

```sh
# print help text with the binary
target/release/simplyr -h
# or with cargo
cargo run --release -- -h
```

```sh
# Don't forget to compile first
cargo build --release

# Test pay-as-bid with example files
target/release/simplyr -a pay-as-bid -o example_market_input.json

# Test our custom fair matching with example files
target/release/simplyr -a custom-fair -o example_market_input.json -g example_grid_fee_matrix.json
```

## simplyr & simplyr-lib

This repo consists of two Rust crates.

* The top-level crate `simplyr` is a binary crate with a command line interface.
* And there is `simplyr-lib`, a library crate that contains most of the code and
  has the `no_std` attribute enabled.

For development it's useful to switch to the `simplyr-lib` subdirectory.

```sh
# Run tests
cargo test
# Build documentation
cargo doc
# Open docs
firefox target/doc/simplyr_lib/index.html
# Run linter
cargo clippy
# Format the code
cargo fmt
```
