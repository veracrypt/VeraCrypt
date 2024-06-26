#!/bin/sh
#
# Copyright (c) 2013-2024 IDRIX
# Governed by the Apache License 2.0 the full text of which is contained
# in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

# Errors should cause script to exit
set -e

# Absolute path to this script
export SCRIPT=$(readlink -f "$0")
# Absolute path this script is in
export SCRIPTPATH=$(dirname "$SCRIPT")
# Source directory which contains the Makefile
export SOURCEPATH=$(readlink -f "$SCRIPTPATH/..")
# Directory where the VeraCrypt has been checked out
export PARENTDIR=$(readlink -f "$SCRIPTPATH/../../..")

# The sources of wxWidgets 3.2.5 must be extracted to the parent directory
export WX_ROOT=$PARENTDIR/wxWidgets-3.2.5
echo "Using wxWidgets sources in $WX_ROOT"

cd $SOURCEPATH

build_and_install() {
    target=$1
    wxstatic=$2
    indicator=$3
    nogui=""

    # Determine wxWidgets build directory based on target
    if [ "$target" = "Console" ]; then
        export WX_BUILD_DIR="$PARENTDIR/wxBuildConsole"
        nogui="NOGUI=1"
    else
        export WX_BUILD_DIR="$PARENTDIR/wxBuildGUI"
    fi

    wxstatic_value=""
    if [ "$wxstatic" = "WXSTATIC" ]; then
        wxstatic_value="WXSTATIC=1"
        make $wxstatic_value $nogui wxbuild || exit 1
    fi

    indicator_value=""
    if [ "$indicator" = "INDICATOR" ]; then
        indicator_value="INDICATOR=1"
    fi

    make $wxstatic_value $indicator_value $nogui clean || exit 1
    make $wxstatic_value $indicator_value $nogui || exit 1
    make $wxstatic_value $indicator_value $nogui install DESTDIR="$PARENTDIR/VeraCrypt_Setup/$target" || exit 1
}

# Handle arguments
case "$1$2" in
"WXSTATIC")
    echo "Building GUI version of VeraCrypt for DEB using wxWidgets static libraries"
    build_and_install "GUI" "WXSTATIC" ""
    ;;
"INDICATOR")
    echo "Building GUI version of VeraCrypt for DEB using system wxWidgets and indicator"
    build_and_install "GUI" "" "INDICATOR"
    ;;
"WXSTATICINDICATOR"|"INDICATORWXSTATIC")
    echo "Building GUI version of VeraCrypt for DEB using wxWidgets static libraries and indicator"
    build_and_install "GUI" "WXSTATIC" "INDICATOR"
    ;;
*)
    echo "Building GUI version of VeraCrypt for DEB using system wxWidgets"
    build_and_install "GUI" "" ""
    ;;
esac

echo "Building console version of VeraCrypt for DEB using wxWidgets static libraries"
build_and_install "Console" "WXSTATIC" ""

echo "Creating VeraCrypt DEB packages"

# -DCPACK_RPM_PACKAGE_DEBUG=TRUE for debugging cpack DEB
# -DCPACK_RPM_PACKAGE_DEBUG=TRUE for debugging cpack DEB

mkdir -p $PARENTDIR/VeraCrypt_Packaging/{GUI,Console}

cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging/GUI -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/GUI" -DNOGUI=FALSE || exit 1
cpack --config $PARENTDIR/VeraCrypt_Packaging/GUI/CPackConfig.cmake || exit 1

cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging/Console -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/Console" -DNOGUI=TRUE || exit 1
cpack --config $PARENTDIR/VeraCrypt_Packaging/Console/CPackConfig.cmake || exit 1
