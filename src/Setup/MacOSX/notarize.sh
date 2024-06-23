#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" # Directory where the script is located
BUNDLE_PATH="${SCRIPT_DIR}/../../Main/VeraCrypt.app"  # Path to the VeraCrypt.app bundle
APPLE_ID="appleid"      # Apple ID
APP_SPECIFIC_PASSWORD="password" # app-specific password
TEAM_ID="teamid"                    # team ID
SIGNING_ID="signingid" # Signing ID

# Check if VeraCrypt.app bundle exists
if [ ! -d "$BUNDLE_PATH" ]; then
    echo "VeraCrypt.app bundle not found: $BUNDLE_PATH"
    exit 1
fi

# Retrieve the version of VeraCrypt from Info.plist
VC_VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "${BUNDLE_PATH}/Contents/Info.plist")

echo "Notarizing VeraCrypt ${VC_VERSION}..."

# Change to the script directory
cd "${SCRIPT_DIR}"

xattr -rc "$BUNDLE_PATH"
codesign --timestamp --option runtime --deep --force --entitlements "${SCRIPT_DIR}/VeraCrypt.entitlements.plist" --sign "${SIGNING_ID}" "$BUNDLE_PATH"

# Check dependencies of the VeraCrypt binary
VC_BINARY="$BUNDLE_PATH/Contents/MacOS/VeraCrypt"
DEPENDENCY_OUTPUT=$(otool -L "$VC_BINARY" | grep libfuse-t.dylib)

# Determine the correct .pkgproj file based on the dependency
PKGPROJ_FILE="${SCRIPT_DIR}/veracrypt.pkgproj"
DMG_LABEL="VeraCrypt_${VC_VERSION}.dmg"
if [[ "$DEPENDENCY_OUTPUT" != "" ]]; then
    echo "VeraCrypt is linked against FUSE-T."
    PKGPROJ_FILE="${SCRIPT_DIR}/veracrypt_fuse-t.pkgproj"
    DMG_LABEL="VeraCrypt_FUSE-T_${VC_VERSION}.dmg"
else
    echo "VeraCrypt is linked against standard MacFUSE."
fi

/usr/local/bin/packagesbuild "$PKGPROJ_FILE"

PKG_PATH="${SCRIPT_DIR}/VeraCrypt_${VC_VERSION}.pkg"  # Constructed path to the VeraCrypt pkg
productsign --sign "Developer ID Installer: IDRIX (Z933746L2S)" --timestamp "${SCRIPT_DIR}/VeraCrypt ${VC_VERSION}.pkg" "$PKG_PATH"

if [ ! -f "$PKG_PATH" ]; then
    echo "pkg file not found: $PKG_PATH"
    exit 1
fi

# Step 1: Upload PKG to Apple for notarization
echo "Uploading PKG to Apple for notarization..."
xcrun notarytool submit "$PKG_PATH" --apple-id "$APPLE_ID" --password "$APP_SPECIFIC_PASSWORD" --team-id "$TEAM_ID" --wait --output-format json > notarization_result.json

# Check if the notarization submission was successful
if [ $? -ne 0 ]; then
    echo "Failed to submit PKG for notarization."
    cat notarization_result.json
    exit 1
fi

# Extract the notarization UUID from the result
REQUEST_UUID=$(grep -o '"id":"[^"]*' notarization_result.json | sed 's/"id":"//')
echo "Notarization Request UUID: $REQUEST_UUID"

# Step 2: Check the notarization status
echo "Checking notarization status..."
STATUS=$(grep -o '"status":"[^"]*' notarization_result.json | sed 's/"status":"//' | sed 's/"}//')
echo "Initial status: $STATUS"

while [ "$STATUS" == "in progress" ]; do
    sleep 30
    xcrun notarytool info "$REQUEST_UUID" --apple-id "$APPLE_ID" --password "$APP_SPECIFIC_PASSWORD" --team-id "$TEAM_ID" --output-format json > notarization_status.json
    
    if [ ! -f notarization_status.json ]; then
        echo "Failed to retrieve notarization status."
        exit 1
    fi

    STATUS=$(grep -o '"status":"[^"]*' notarization_status.json | sed 's/"status":"//' | sed 's/"}//')
    echo "Current status: $STATUS"
done

# Step 3: Staple the notarization ticket to the pkg or retrieve the log
if [ "$STATUS" == "Accepted" ]; then
    echo "Stapling the notarization ticket to the pkg..."
    # Staple the notarization ticket to the installer package
    xcrun stapler staple "$PKG_PATH"
    echo "Notarization and stapling completed successfully."

    # Clean up any existing temporary files and directories
    rm -f template.dmg
    rm -fr VeraCrypt_dmg

    # Create a directory to mount the template DMG
    echo "Creating directory to mount the template DMG..."
    mkdir -p VeraCrypt_dmg

    # Decompress the template DMG file
    echo "Decompressing the template DMG file..."
    bunzip2 -k -f template.dmg.bz2

    # Attach the template DMG to the system, mount it at VeraCrypt_dmg directory
    echo "Attaching the template DMG to the system..."
    hdiutil attach template.dmg -noautoopen -quiet -mountpoint VeraCrypt_dmg

    # Copy the notarized installer package into the mounted DMG
    echo "Copying the notarized installer package into the mounted DMG..."
    cp "VeraCrypt_${VC_VERSION}.pkg" VeraCrypt_dmg/VeraCrypt_Installer.pkg

    # Detach the DMG, ensuring all changes are saved and it's unmounted
    echo "Detaching the DMG..."
    hdiutil detach VeraCrypt_dmg -quiet -force

    # Convert the DMG back to a compressed format (UDZO) and create the final DMG file
    echo "Converting the DMG back to a compressed format..."
    rm -f "${DMG_LABEL}"
    hdiutil convert template.dmg -quiet -format UDZO -imagekey zlib-level=9 -o "${DMG_LABEL}"

    # Sign the final DMG file
    echo "Signing the final DMG file..."
    codesign -s "${SIGNING_ID}" --timestamp "${DMG_LABEL}"

    # Clean up temporary files and directories
    rm -f template.dmg
    rm -fr VeraCrypt_dmg
else
    echo "Notarization failed. Retrieving log for more details..."
    # Retrieve the notarization log for details on why it failed
    xcrun notarytool log "$REQUEST_UUID" --apple-id "$APPLE_ID" --password "$APP_SPECIFIC_PASSWORD" --team-id "$TEAM_ID" --output-format json > notarization_log.json
    cat notarization_log.json
fi

# Clean up temporary files
rm -f notarization_result.json
rm -f notarization_status.json
rm -f notarization_log.json

exit 0