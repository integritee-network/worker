#!/bin/bash
# call this script from repo root directory

# Fail fast if any commands exists with error
# Print all executed commands
set -ex

# Download rustup script and execute it
curl https://sh.rustup.rs -sSf > ./rustup.sh
chmod +x ./rustup.sh
./rustup.sh -y

# Load new environment
source $HOME/.cargo/env

# Load new environment
source $HOME/.cargo/env

# With the new rust-toolchain.toml format, this automatically installs the correct components.
rustup show
