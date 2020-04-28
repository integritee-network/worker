#!/bin/bash

# Fail fast if any commands exists with error
set -e

# Print all executed commands
set -x

# Download rustup script and execute it
curl https://sh.rustup.rs -sSf > ./rustup.sh
chmod +x ./rustup.sh
./rustup.sh -y

# Load new environment
source $HOME/.cargo/env

# Install and set specific nightly version as default
rustup install nightly-2020-04-07
rustup default nightly-2020-04-07

# install targets
rustup target install wasm32-unknown-unknown

# Install aux components, clippy for linter, rustfmt for formatting
rustup component add clippy --toolchain=nightly-2020-04-07
rustup component add rustfmt --toolchain=nightly-2020-04-07

# Show the installed versions
rustup show
