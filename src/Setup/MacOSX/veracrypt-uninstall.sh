#!/bin/bash
#
# Copyright (c) 2026 AM Crypto and are governed by the Apache License 2.0
# the full text of which is contained in the file License.txt included in
# VeraCrypt binary and source code distribution packages.
#
# Uninstalls VeraCrypt, including the SMJobBless privileged helper and its
# launchd job. Must be run as root (it removes files under /Library and
# unloads a system launchd daemon).

HELPER_LABEL="org.idrix.VeraCrypt.helper"
HELPER_TOOL="/Library/PrivilegedHelperTools/${HELPER_LABEL}"
HELPER_PLIST="/Library/LaunchDaemons/${HELPER_LABEL}.plist"

if [ "$(id -u)" -ne 0 ]; then
    echo "This uninstaller must be run as root (use sudo)." >&2
    exit 1
fi

# Stop and remove the privileged helper launchd job.
launchctl bootout "system/${HELPER_LABEL}" 2>/dev/null
launchctl unload "${HELPER_PLIST}" 2>/dev/null

rm -f "${HELPER_PLIST}"
rm -f "${HELPER_TOOL}"

# Remove the application bundle and CLI symlink created by the installer.
rm -rf /Applications/VeraCrypt.app
rm -f /usr/local/bin/veracrypt

echo "VeraCrypt and its privileged helper have been removed."
exit 0
