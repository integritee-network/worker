#!/bin/bash

# Check if the snapshot directory is provided as the first argument
if [ -z "$1" ]; then
    echo "Usage: $0 /path/to/snapshot_directory"
    exit 1
fi

SNAPSHOT_DIR="$1"

# Check if it's a valid directory
if [ ! -d "$SNAPSHOT_DIR" ]; then
    echo "Error: '$SNAPSHOT_DIR' is not a valid directory."
    exit 1
fi

# Change to snapshot directory
cd "$SNAPSHOT_DIR" || { echo "Failed to access directory."; exit 1; }

# Loop through each subdirectory
for dir in */; do
    dir=${dir%/}  # Strip trailing slash

    # Extract the timestamp (format: YYYYMMDD-HH:MM:SS)
    timestamp=$(echo "$dir" | grep -oE '[0-9]{8}-[0-9]{2}:[0-9]{2}:[0-9]{2}')

    if [[ -z "$timestamp" ]]; then
        continue
    fi

    # Convert to format 'YYYY-MM-DD HH:MM:SS'
    formatted_ts="$(echo "$timestamp" | sed -E 's/([0-9]{4})([0-9]{2})([0-9]{2})-([0-9:]{8})/\1-\2-\3 \4/')"

    # Convert to epoch time (GNU date)
    dir_time=$(date -d "$formatted_ts" +%s 2>/dev/null)

    if [[ -z "$dir_time" ]]; then
        echo "Skipping $dir: invalid date format ($formatted_ts)"
        continue
    fi

    now=$(date +%s)
    age=$(( (now - dir_time) / 86400 ))

    if (( age > 10 )); then
        echo "Deleting $dir (age: $age days)"
        rm -rf "$dir"
    fi
done
