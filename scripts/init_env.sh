#!/bin/bash

# script that sets the correct environment variables to execute other scripts

export SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
export PROJ_ROOT="$(dirname "$SCRIPT_DIR")"
export CLIENT_DIR="$PROJ_ROOT/cli"
export LOG_DIR="$PROJ_ROOT/log"
export CI_DIR="$PROJ_ROOT/ci"


echo "Set environment variables:"
echo "  BASH_SCRIPT_DIR: $SCRIPT_DIR"
echo "  PROJ_ROOT: $PROJ_ROOT"
echo "  CLIENT_DIR: $CLIENT_DIR"