#!/bin/bash
# Check if a directory argument was provided, default to current directory if not
DIRECTORY="${1:-.}"
# Remove any trailing slash from the directory path
DIRECTORY="${DIRECTORY%/}"

timestamp=$(date +%Y%m%d-%T)
echo "snappshotting all light client db's at $timestamp"
cp -r "$DIRECTORY/integritee_lcdb" "$DIRECTORY/integritee_lcdb_$timestamp"