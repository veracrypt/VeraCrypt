#!/bin/bash
set -euo pipefail # Exit on error, undefined variable, or pipe failure

# --- Configuration ---
SCRIPT_NAME=$(basename "$0")
FAIL_FLAG=false

# --- Colors ---
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_CYAN='\033[0;36m'
COLOR_MAGENTA='\033[0;35m'
COLOR_RESET='\033[0m' # No Color

# --- Helper Functions for Output ---
log_info() { echo -e "${COLOR_CYAN}$1${COLOR_RESET}"; }
log_success() { echo -e "${COLOR_GREEN}$1${COLOR_RESET}"; }
log_warning() { echo -e "${COLOR_YELLOW}Warning: $1${COLOR_RESET}"; }
log_error() { echo -e "${COLOR_RED}Error: $1${COLOR_RESET}" >&2; }
log_detail() { echo -e "  $1"; }
log_detail_success() { echo -e "  ${COLOR_GREEN}$1${COLOR_RESET}"; }
log_detail_error() { echo -e "  ${COLOR_RED}$1${COLOR_RESET}"; }
log_detail_warning() { echo -e "  ${COLOR_YELLOW}$1${COLOR_RESET}"; }
log_detail_magenta() { echo -e "    ${COLOR_MAGENTA}$1${COLOR_RESET}"; }

# --- Parameter Validation ---
if [ "$#" -ne 1 ]; then
    log_error "Usage: $SCRIPT_NAME <Path_To_VeraCrypt_Root>"
    log_error "Example: $SCRIPT_NAME /path/to/VeraCrypt"
    exit 1
fi

ROOT_PATH="$1"

if [ ! -d "$ROOT_PATH" ]; then
    log_error "Root path '$ROOT_PATH' not found or is not a directory."
    exit 1
fi

# Define the path to the common Language.xml
COMMON_FILE="$ROOT_PATH/src/Common/Language.xml"

# Check if the common Language.xml exists
if [ ! -f "$COMMON_FILE" ]; then
    log_error "Common Language.xml not found or is not a file at path: $COMMON_FILE"
    exit 1
fi

log_info "Extracting keys from $COMMON_FILE"

# Define regex pattern to extract 'key' attributes from <entry> elements
KEY_EXTRACTION_PATTERN='<entry\s+lang="[^"]+"\s+key="([^"]+)"'

# Extract all keys using grep with PCRE (-P) and only outputting the captured group (-o)
# Use process substitution and readarray to populate the KEYS array
# Ensure grep returns 0 even if no match, or handle non-zero for no match
KEYS_STRING=$(grep -oP "$KEY_EXTRACTION_PATTERN" "$COMMON_FILE" | sed -E 's/.*key="([^"]+)".*/\1/' || true)
if [ -z "$KEYS_STRING" ]; then
    KEYS=()
else
    readarray -t KEYS < <(echo "$KEYS_STRING")
fi


if [ ${#KEYS[@]} -eq 0 ]; then
    log_warning "No keys found in $COMMON_FILE using pattern: $KEY_EXTRACTION_PATTERN"
    # If this should be an error, uncomment next lines:
    # log_error "No keys found in $COMMON_FILE."
    # exit 1
else
    log_info "Found ${#KEYS[@]} keys."
fi

# Define the regex for finding invalid escape sequences.
# Valid sequences: \n, \r, \t, \\, \"
INVALID_ESCAPE_REGEX='(?<!\\)(?:\\\\)*\\([^nrt\\"])' # This is better
ALLOWED_ESCAPES_MESSAGE="Allowed sequences are: \\n, \\r, \\t, \\\\ (for literal backslash), \\\" (for literal quote)"

# Retrieve all translation XML files in the Translations folder
TRANSLATION_FOLDER="$ROOT_PATH/Translations"
FILES_TO_PROCESS=()

# Add common file first
FILES_TO_PROCESS+=("$COMMON_FILE")

if [ ! -d "$TRANSLATION_FOLDER" ]; then
    log_warning "Translations folder not found at path: $TRANSLATION_FOLDER. Skipping translation files."
else
    # Use find to get translation files. nullglob helps avoid errors if no files match.
    shopt -s nullglob
    for lang_file in "$TRANSLATION_FOLDER"/Language.*.xml; do
        FILES_TO_PROCESS+=("$lang_file")
    done
    shopt -u nullglob # Reset nullglob
    if [ ${#FILES_TO_PROCESS[@]} -eq 1 ]; then # Only common file was added
        log_warning "No Language.*.xml files found in $TRANSLATION_FOLDER."
    fi
fi

if [ ${#FILES_TO_PROCESS[@]} -eq 0 ]; then
    log_warning "No files found to process."
    exit 0 # Or 1 if this is an error condition
fi

# Iterate through each file and perform validations
for file in "${FILES_TO_PROCESS[@]}"; do
    if [ ! -f "$file" ]; then
        log_warning "File not found or is not a file, skipping: $file"
        continue
    fi
    echo # Newline for readability
    log_info "Processing file: $file"
    CURRENT_FILE_PASSES=true

    # 1. Validate XML using fxparser
    log_detail "Validating XML structure..."
    # Capture stdout and stderr, get exit code
    FXPARSER_OUTPUT=$(fxparser -V "$file" 2>&1)
    FXPARSER_EXIT_CODE=$?

    if [ "$FXPARSER_EXIT_CODE" -ne 0 ]; then
        CURRENT_FILE_PASSES=false
        FAIL_FLAG=true
        log_detail_error "XML Validation Failed for $file (fxparser exit code: $FXPARSER_EXIT_CODE):"
        while IFS= read -r line; do
            log_detail_error "    $line"
        done <<< "$FXPARSER_OUTPUT"
    else
        log_detail_success "XML structure is valid."
    fi

    # 2. Check for invalid backslash escape sequences
    log_detail "Checking for invalid escape sequences..."
    # Use grep -P for PCRE, -n for line numbers. --color=never to avoid grep's own coloring here.
    # We check grep's exit code: 0 if found, 1 if not found, >1 for error.
    INVALID_ESCAPE_MATCHES=$(grep -P -n --color=never "$INVALID_ESCAPE_REGEX" "$file" || true)

    if [ -n "$INVALID_ESCAPE_MATCHES" ]; then
        log_detail_error "File '$file' contains potentially invalid backslash escape sequences."
        log_detail_error "$ALLOWED_ESCAPES_MESSAGE"
        log_detail_error "Instances found:"
        while IFS= read -r line_match; do
            # Extract line number and the line content from grep's output (e.g., "123:content")
            LINE_NUMBER=$(echo "$line_match" | cut -d: -f1)
            LINE_CONTENT=$(echo "$line_match" | cut -d: -f2-)
            # Trim whitespace (optional, but PowerShell did it)
            TRIMMED_LINE_CONTENT=$(echo "$LINE_CONTENT" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            log_detail_magenta "Line $LINE_NUMBER: $TRIMMED_LINE_CONTENT"
        done <<< "$INVALID_ESCAPE_MATCHES"
        CURRENT_FILE_PASSES=false
        FAIL_FLAG=true
    else
        log_detail_success "No invalid escape sequences found."
    fi

    # 3. Check for the presence of each key in the current file (if keys were found)
    if [ ${#KEYS[@]} -gt 0 ]; then
        log_detail "Checking for key completeness..."
        KEYS_MISSING_IN_CURRENT_FILE=0
        for key_entry in "${KEYS[@]}"; do
            # Search for key="KEY_NAME"
            SEARCH_PATTERN_FOR_KEY="key=\"$key_entry\""
            if ! grep -q "$SEARCH_PATTERN_FOR_KEY" "$file"; then
                log_detail_error "Key '$key_entry' (from $COMMON_FILE) not found in $file"
                CURRENT_FILE_PASSES=false
                FAIL_FLAG=true
                ((KEYS_MISSING_IN_CURRENT_FILE++))
            fi
        done
        if [ "$KEYS_MISSING_IN_CURRENT_FILE" -eq 0 ]; then
            log_detail_success "All keys from $COMMON_FILE are present."
        else
            log_detail_error "$KEYS_MISSING_IN_CURRENT_FILE key(s) missing."
        fi
    else
        log_detail_warning "Skipping key completeness check as no keys were extracted from $COMMON_FILE."
    fi

    # Output the result for the current file
    if [ "$CURRENT_FILE_PASSES" = true ]; then
        log_success "$file PASSED all checks."
    else
        log_error "$file FAILED one or more checks."
    fi
done

# Exit with appropriate status code
echo # Newline for readability
if [ "$FAIL_FLAG" = true ]; then
    log_error "Overall Result: One or more files failed validation."
    exit 1
else
    log_success "Overall Result: All processed files passed all checks successfully."
    exit 0
fi
