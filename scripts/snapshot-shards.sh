#!/bin/bash
# Check if a directory argument was provided, default to current directory if not
DIRECTORY="${1:-.}"
# Remove any trailing slash from the directory path
DIRECTORY="${DIRECTORY%/}"

timestamp=$(date +%Y%m%d-%T)
echo "snappshotting all shards at $timestamp"
cp -r "$DIRECTORY/shards" "$DIRECTORY/shards_$timestamp"
cp -r "$DIRECTORY/sidechain_db" "$DIRECTORY/sidechain_db_$timestamp"
