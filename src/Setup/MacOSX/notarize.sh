#!/bin/bash

# Never continue to an upload after a failed build or signing command.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" # Directory where the script is located
BUNDLE_PATH="${SCRIPT_DIR}/../../Main/VeraCrypt.app"  # Path to the VeraCrypt.app bundle
TEAM_ID="HLTN5GLG99"                    # team ID
SIGNING_ID="Developer ID Application: Mounir Joseph IDRASSI (HLTN5GLG99)" # Signing ID
INSTALLER_SIGNING_ID="Developer ID Installer: Mounir Joseph IDRASSI (HLTN5GLG99)"

# Set up credentials once: xcrun notarytool store-credentials "VeraCrypt"
# Enter the Apple ID, app-specific password, and team ID at the interactive prompts.
# Credentials stay in Keychain; only the profile name is passed to notarytool.
# VC_NOTARY_KEYCHAIN optionally selects a custom Keychain containing the profile.
NOTARY_PROFILE="${VC_NOTARY_PROFILE:-VeraCrypt}"
NOTARY_AUTH_ARGS=(--keychain-profile "$NOTARY_PROFILE")
if [ -n "${VC_NOTARY_KEYCHAIN:-}" ]; then
    NOTARY_AUTH_ARGS+=(--keychain "$VC_NOTARY_KEYCHAIN")
fi

fail() {
    echo "Error: $*" >&2
    exit 1
}

# Check every architecture, including the executable actually placed in the pkg.
verify_app() {
    local bundle="$1"
    local architectures architecture signature
    codesign --verify --deep --strict --verbose=2 "$bundle"
    architectures=$(lipo -archs "$bundle/Contents/MacOS/VeraCrypt")
    [ -n "$architectures" ] || fail "No architectures found in $bundle"
    for architecture in $architectures; do
        signature=$(codesign --display --verbose=4 --arch "$architecture" "$bundle" 2>&1)
        if ! grep -Eq '^CodeDirectory .*flags=.*[(,]runtime[),]' <<< "$signature"; then
            fail "Hardened runtime is missing for $architecture in $bundle"
        fi
        if ! grep -Fxq "TeamIdentifier=$TEAM_ID" <<< "$signature"; then
            fail "Unexpected signing team for $architecture in $bundle"
        fi
        if ! grep -q '^Timestamp=' <<< "$signature"; then
            fail "Secure timestamp is missing for $architecture in $bundle"
        fi
    done
}

# Check if VeraCrypt.app bundle exists
VC_BINARY="$BUNDLE_PATH/Contents/MacOS/VeraCrypt"
[ -f "$VC_BINARY" ] || fail "VeraCrypt executable not found: $VC_BINARY"

# Retrieve the version of VeraCrypt from Info.plist
VC_VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "${BUNDLE_PATH}/Contents/Info.plist")
[ -n "$VC_VERSION" ] || fail "The app bundle has no version. Rebuild VeraCrypt first."

echo "Notarizing VeraCrypt ${VC_VERSION}..."

# Keep otool failures fatal while allowing the MacFUSE case to have no FUSE-T match.
DEPENDENCY_OUTPUT=$(otool -L "$VC_BINARY")

# Determine the correct .pkgproj file based on the dependency
PKGPROJ_FILE="${SCRIPT_DIR}/veracrypt.pkgproj"
DMG_LABEL="VeraCrypt_${VC_VERSION}.dmg"
if [[ "$DEPENDENCY_OUTPUT" == *libfuse-t.dylib* ]]; then
    echo "VeraCrypt is linked against FUSE-T."
    PKGPROJ_FILE="${SCRIPT_DIR}/veracrypt_fuse-t.pkgproj"
    DMG_LABEL="VeraCrypt_FUSE-T_${VC_VERSION}.dmg"
else
    echo "VeraCrypt is linked against standard MacFUSE."
fi

# The project controls the output filename independently of the app's Info.plist.
PKG_VERSION=$(/usr/libexec/PlistBuddy -c "Print :PACKAGES:0:PACKAGE_SETTINGS:VERSION" "$PKGPROJ_FILE")
PKG_NAME=$(/usr/libexec/PlistBuddy -c "Print :PROJECT:PROJECT_SETTINGS:NAME" "$PKGPROJ_FILE")
if [ "$PKG_VERSION" != "$VC_VERSION" ] || [ "$PKG_NAME" != "VeraCrypt $VC_VERSION" ]; then
    fail "Version mismatch: app is $VC_VERSION, package is $PKG_VERSION ($PKG_NAME). Rebuild VeraCrypt and update the package project before notarizing."
fi

# Check credentials before modifying the app or building the installer.
echo "Checking notarization credentials in Keychain profile: $NOTARY_PROFILE"
if ! xcrun notarytool history "${NOTARY_AUTH_ARGS[@]}" --output-format json > /dev/null; then
    fail "Cannot authenticate with Keychain profile '$NOTARY_PROFILE'. Set it up using 'xcrun notarytool store-credentials', or check Keychain access and network connectivity."
fi

# Isolate all generated files so that an earlier installer can never be submitted.
WORK_DIR=$(mktemp -d "${SCRIPT_DIR}/.notarize.XXXXXX")
DMG_MOUNTED=false
cleanup() {
    local status=$?
    trap - EXIT
    if [ "$DMG_MOUNTED" = true ]; then
        hdiutil detach "$WORK_DIR/mount" -quiet -force || status=1
    fi
    if [ "$status" -eq 0 ]; then
        rm -rf "$WORK_DIR"
    else
        echo "Notarization failed. Working files and logs retained in: $WORK_DIR" >&2
    fi
    exit "$status"
}
trap cleanup EXIT

xattr -rc "$BUNDLE_PATH"
codesign --timestamp --options runtime --deep --force --entitlements "${SCRIPT_DIR}/VeraCrypt.entitlements.plist" --sign "$SIGNING_ID" "$BUNDLE_PATH"
verify_app "$BUNDLE_PATH"

/usr/local/bin/packagesbuild --build-folder "$WORK_DIR" "$PKGPROJ_FILE"
UNSIGNED_PKG_PATH="$WORK_DIR/$PKG_NAME.pkg"
[ -f "$UNSIGNED_PKG_PATH" ] || fail "Package build did not produce $UNSIGNED_PKG_PATH"
PKG_PATH="$WORK_DIR/VeraCrypt_${VC_VERSION}.pkg"
productsign --sign "$INSTALLER_SIGNING_ID" --timestamp "$UNSIGNED_PKG_PATH" "$PKG_PATH"
pkgutil --check-signature "$PKG_PATH"

# Validate the payload, not just the source bundle or the installer signature.
pkgutil --expand-full "$PKG_PATH" "$WORK_DIR/expanded"
PACKAGED_BUNDLE="$WORK_DIR/expanded/veracrypt.pkg/Payload/Applications/VeraCrypt.app"
cmp "$VC_BINARY" "$PACKAGED_BUNDLE/Contents/MacOS/VeraCrypt" || fail "The packaged executable differs from the signed app."
cmp "$BUNDLE_PATH/Contents/Info.plist" "$PACKAGED_BUNDLE/Contents/Info.plist" || fail "The packaged Info.plist differs from the signed app."
verify_app "$PACKAGED_BUNDLE"

# Upload only the newly built, verified package.
RESULT_PATH="$WORK_DIR/notarization_result.json"
STATUS_PATH="$WORK_DIR/notarization_status.json"
LOG_PATH="$WORK_DIR/notarization_log.json"
echo "Uploading PKG to Apple for notarization..."
if ! xcrun notarytool submit "$PKG_PATH" "${NOTARY_AUTH_ARGS[@]}" --wait --output-format json > "$RESULT_PATH"; then
    cat "$RESULT_PATH"
    fail "Failed to submit PKG for notarization."
fi

REQUEST_UUID=$(plutil -extract id raw -expect string -o - "$RESULT_PATH")
STATUS=$(plutil -extract status raw -expect string -o - "$RESULT_PATH")
[ -n "$REQUEST_UUID" ] || fail "Notarization returned an empty request UUID."
echo "Notarization Request UUID: $REQUEST_UUID"
echo "Initial status: $STATUS"

while [[ "$STATUS" == [Ii]n\ [Pp]rogress ]]; do
    sleep 30
    xcrun notarytool info "$REQUEST_UUID" "${NOTARY_AUTH_ARGS[@]}" --output-format json > "$STATUS_PATH"
    STATUS=$(plutil -extract status raw -expect string -o - "$STATUS_PATH")
    echo "Current status: $STATUS"
done

if [ "$STATUS" != "Accepted" ]; then
    echo "Notarization failed. Retrieving log for more details..."
    if xcrun notarytool log "$REQUEST_UUID" "${NOTARY_AUTH_ARGS[@]}" --output-format json > "$LOG_PATH"; then
        cat "$LOG_PATH"
    fi
    fail "Notarization status: $STATUS"
fi

echo "Stapling the notarization ticket to the pkg..."
xcrun stapler staple "$PKG_PATH"
xcrun stapler validate "$PKG_PATH"

echo "Creating the distribution DMG..."
mkdir "$WORK_DIR/mount"
bunzip2 -c "$SCRIPT_DIR/template.dmg.bz2" > "$WORK_DIR/template.dmg"
hdiutil attach "$WORK_DIR/template.dmg" -noautoopen -quiet -mountpoint "$WORK_DIR/mount"
DMG_MOUNTED=true
cp "$PKG_PATH" "$WORK_DIR/mount/VeraCrypt_Installer.pkg"
hdiutil detach "$WORK_DIR/mount" -quiet -force
DMG_MOUNTED=false
hdiutil convert "$WORK_DIR/template.dmg" -quiet -format UDZO -imagekey zlib-level=9 -o "$WORK_DIR/$DMG_LABEL"
codesign -s "$SIGNING_ID" --timestamp "$WORK_DIR/$DMG_LABEL"
codesign --verify --verbose=2 "$WORK_DIR/$DMG_LABEL"

# Replace release outputs only after notarization and DMG creation both succeed.
mv -f "$PKG_PATH" "$SCRIPT_DIR/VeraCrypt_${VC_VERSION}.pkg"
mv -f "$WORK_DIR/$DMG_LABEL" "$SCRIPT_DIR/$DMG_LABEL"
echo "Notarization completed: $SCRIPT_DIR/$DMG_LABEL"

exit 0
