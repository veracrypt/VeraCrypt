#!/bin/sh
#
# Copyright (c) 2013-2025 AM Crypto
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

# Check the condition of wxBuildConsole and wxWidgets-3.2.5 in the original PARENTDIR
if [ -d "$PARENTDIR/wxBuildConsole" ]; then
    echo "Using existing PARENTDIR: $PARENTDIR, wxBuildConsole is present."
elif [ -d "$PARENTDIR/wxWidgets-3.2.5" ]; then
    echo "Using existing PARENTDIR: $PARENTDIR, wxWidgets-3.2.5 is present."
else
    # Change PARENTDIR to /tmp and check conditions again
    export PARENTDIR="/tmp"
    if [ -d "$PARENTDIR/wxBuildConsole" ]; then
        echo "Switched to PARENTDIR: /tmp, wxBuildConsole is present in /tmp."
    elif [ -d "$PARENTDIR/wxWidgets-3.2.5" ]; then
        echo "Switched to PARENTDIR: /tmp, wxWidgets-3.2.5 is present in /tmp."
    else
        echo "Error: Neither wxBuildConsole nor wxWidgets-3.2.5 found in /tmp. Exiting."
        exit 1
    fi
fi

# The sources of wxWidgets 3.2.5 must be extracted to the parent directory
export WX_ROOT=$PARENTDIR/wxWidgets-3.2.5

cd $SOURCEPATH

# Detect requested FUSE version (defaults to FUSE2). Can be set via WITHFUSE3=1 or by passing FUSE3/--with-fuse3.
build_with_fuse3=0
if [ -n "$WITHFUSE3" ] && [ "$WITHFUSE3" != "0" ]; then
    build_with_fuse3=1
fi

preserved_args=""
while [ $# -gt 0 ]; do
    case "$1" in
        FUSE3|WITHFUSE3|--with-fuse3)
            build_with_fuse3=1
            ;;
        FUSE2|WITHFUSE2|--with-fuse2)
            build_with_fuse3=0
            ;;
        WXSTATIC|INDICATOR)
            if [ -z "$preserved_args" ]; then
                preserved_args="$1"
            else
                preserved_args="$preserved_args $1"
            fi
            ;;
        *)
            echo "Warning: Unrecognized option '$1' (ignored)" >&2
            ;;
    esac
    shift
done

set --
if [ -n "$preserved_args" ]; then
    for arg in $preserved_args; do
        set -- "$@" "$arg"
    done
fi

if [ "$build_with_fuse3" = "1" ]; then
    FUSE3_MAKE_FLAG="WITHFUSE3=1"
    FUSE3_CMAKE_FLAG="-DVC_WITH_FUSE3=TRUE"
    echo "Building VeraCrypt packages against FUSE3"
else
    FUSE3_MAKE_FLAG=""
    FUSE3_CMAKE_FLAG="-DVC_WITH_FUSE3=FALSE"
    echo "Building VeraCrypt packages against FUSE2"
fi

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
        # Check if wx-config exists in WX_BUILD_DIR
        if [ -L "${WX_BUILD_DIR}/wx-config" ]; then
            echo "wx-config already exists in ${WX_BUILD_DIR}. Skipping wxbuild."
        else
            echo "Using wxWidgets sources in $WX_ROOT"
            make $wxstatic_value $nogui $FUSE3_MAKE_FLAG wxbuild || exit 1
        fi
    fi

    indicator_value=""
    if [ "$indicator" = "INDICATOR" ]; then
        indicator_value="INDICATOR=1"
    fi

    rm -rf "$PARENTDIR/VeraCrypt_Setup/$target"
    make $wxstatic_value $indicator_value $nogui $FUSE3_MAKE_FLAG clean || exit 1
    make $wxstatic_value $indicator_value $nogui $FUSE3_MAKE_FLAG || exit 1
    make $wxstatic_value $indicator_value $nogui $FUSE3_MAKE_FLAG install DESTDIR="$PARENTDIR/VeraCrypt_Setup/$target" || exit 1
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

# remove old packages
rm -rf $PARENTDIR/VeraCrypt_Packaging

mkdir -p $PARENTDIR/VeraCrypt_Packaging/GUI
mkdir -p $PARENTDIR/VeraCrypt_Packaging/Console

cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging/GUI -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/GUI" -DNOGUI=FALSE $FUSE3_CMAKE_FLAG || exit 1
cpack --config $PARENTDIR/VeraCrypt_Packaging/GUI/CPackConfig.cmake || exit 1

cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging/Console -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/Console" -DNOGUI=TRUE $FUSE3_CMAKE_FLAG || exit 1
cpack --config $PARENTDIR/VeraCrypt_Packaging/Console/CPackConfig.cmake || exit 1
