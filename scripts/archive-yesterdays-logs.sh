#!/bin/bash
# a script to compress enclave extrinsic logs in the working dir for the previous day and delete them to clean up
# run as root with crontab
# crontab -e
# 0 2 * * * /path/to/your_script.sh /abs-path-to-log-directory

# Check if a directory argument was provided, default to current directory if not
DIRECTORY="${1:-.}"
# Remove any trailing slash from the directory path
DIRECTORY="${DIRECTORY%/}"

# Define the archive file name with yesterday's date
ARCHIVE_NAME="archive_$(date -d 'yesterday' +%Y%m%d).tar.gz"
# Define the date string for yesterday
YESTERDAY_DATE=$(date -d 'yesterday' +%Y%m%d)

# Find and archive all files in the directory created yesterday
#FILES_TO_ARCHIVE=$(find "$DIRECTORY" -type f -newermt "yesterday 00:00:00" ! -newermt "today 00:00:00")
# Find all files in the directory matching yesterday's date in the filename
FILES_TO_ARCHIVE=$(find "$DIRECTORY" -type f -name "extrinsics-$YESTERDAY_DATE-*")

# Check if there are any files to archive
if [ -z "$FILES_TO_ARCHIVE" ]; then
    echo "No files created yesterday in $DIRECTORY."
    exit 0
fi

# Create the archive with the files found
tar -czf "$DIRECTORY/$ARCHIVE_NAME" $FILES_TO_ARCHIVE

# Check if the tar command was successful
if [ $? -eq 0 ]; then
    # If successful, delete the original files
    echo "Archive created successfully as $ARCHIVE_NAME. Deleting original files."
    rm -f $FILES_TO_ARCHIVE
else
    echo "Failed to create archive. Original files are not deleted."
fi
