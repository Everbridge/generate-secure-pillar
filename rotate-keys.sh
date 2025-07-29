#!/bin/bash

set -euo pipefail

GSP=$(which generate-secure-pillar)

directory="$1"
old_key_id="$2"
new_profile="$3"

# Function to find files whose first line matches "#!yaml|gpg" in a given directory
find_yaml_gpg_files() {
    if [ ! -d "$directory" ]; then
        echo "Error: Directory '$directory' does not exist"
        return 1
    fi

    find "$directory" -type f -name "*.sls" | while read -r file; do
        # Check if file is readable and not empty
        if [ -r "$file" ] && [ -s "$file" ]; then
            # Read the first line and check if it matches the literal string
            if head -n 1 "$file" | grep -q "yaml|gpg"; then
                if "$GSP" keys all -f "$file" | grep -q "$old_key_id"; then
                    echo "Updating key in file: $file"
                    "$GSP" --profile "$new_profile" rotate -f "$file" > "$file.rotated"
                    mv "$file.rotated" "$file"
                fi
            fi
        fi
    done
}

# Main script execution
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <directory> <old_key_id> <new_profile>"
    echo "  directory: Path to the directory to search"
    echo "  old_key_id: ID for the old key"
    echo "  new_profile: generate-secure-pillar config profile to apply for the new key"
    exit 1
fi
# Validate arguments
if [ ! -d "$directory" ]; then
    echo "Error: Directory '$directory' does not exist"
    exit 1
fi

echo "Searching for yaml/gpg files in directory: $directory"
echo "Old key ID: $old_key_id"
echo "New key ID: $new_profile"
echo ""

# Find and process the files
find_yaml_gpg_files "$directory"
