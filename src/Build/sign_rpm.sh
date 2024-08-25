#!/bin/bash

# Function to display usage information
usage() {
    echo "Usage: $0 <directory>"
    exit 1
}

# Check if a directory was provided as an argument
if [ $# -ne 1 ]; then
    usage
fi

DIRECTORY="$1"

# Check if the specified directory exists
if [ ! -d "$DIRECTORY" ]; then
    echo "Error: Directory '$DIRECTORY' does not exist."
    exit 1
fi

# Check if there are any RPM files in the directory
shopt -s nullglob  # Make the glob return an empty array if no match
rpm_files=("$DIRECTORY"/*.rpm)

if [ ${#rpm_files[@]} -eq 0 ]; then
    echo "No RPM files found in directory '$DIRECTORY'."
    exit 0
fi

# Iterate over each RPM file in the directory
for rpm_file in "${rpm_files[@]}"; do
    echo "Processing $rpm_file..."
    
    # Remove the existing signature if any
    echo "Removing existing signature from $rpm_file (if any)..."
    rpmsign --delsign "$rpm_file" || {
        echo "Failed to remove signature from $rpm_file."
        exit 1
    }
    
    # Sign the RPM file
    echo "Signing $rpm_file..."
    rpmsign --define "_gpg_name veracrypt@idrix.fr" \
            --define "_gpg_digest_algo sha512" \
            --define "_source_filedigest_algorithm 10" \
            --define "_binary_filedigest_algorithm 10" \
            --addsign "$rpm_file" || {
        echo "Failed to sign $rpm_file. Aborting."
        exit 1
    }

    echo "Successfully signed $rpm_file."
done
