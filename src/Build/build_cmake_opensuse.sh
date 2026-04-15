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

while [ $# -gt 0 ]; do
    case "$1" in
        FUSE3|WITHFUSE3|--with-fuse3)
            build_with_fuse3=1
            ;;
        FUSE2|WITHFUSE2|--with-fuse2)
            build_with_fuse3=0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
    shift
done

if [ "$build_with_fuse3" = "1" ]; then
    FUSE3_MAKE_FLAG="WITHFUSE3=1"
    FUSE3_CMAKE_FLAG="-DVC_WITH_FUSE3=TRUE"
    echo "Building VeraCrypt packages against FUSE3"
else
    FUSE3_MAKE_FLAG=""
    FUSE3_CMAKE_FLAG="-DVC_WITH_FUSE3=FALSE"
    echo "Building VeraCrypt packages against FUSE2"
fi

echo "Building GUI version of VeraCrypt for RPM using wxWidgets static libraries"

# This will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuildGui

# Check if wx-config exists in WX_BUILD_DIR
if [ -L "${WX_BUILD_DIR}/wx-config" ]; then
    echo "wx-config already exists in ${WX_BUILD_DIR}. Skipping wxbuild."
else
    echo "Using wxWidgets sources in $WX_ROOT"
    make WXSTATIC=1 $FUSE3_MAKE_FLAG wxbuild || exit 1
    ln -s $WX_BUILD_DIR/lib  $WX_BUILD_DIR/lib64
fi

rm -rf "$PARENTDIR/VeraCrypt_Setup/GUI"
make WXSTATIC=1 $FUSE3_MAKE_FLAG clean 				|| exit 1
make WXSTATIC=1 $FUSE3_MAKE_FLAG 					|| exit 1
make WXSTATIC=1 $FUSE3_MAKE_FLAG install DESTDIR="$PARENTDIR/VeraCrypt_Setup/GUI"	|| exit 1

echo "Building console version of VeraCrypt for RPM using wxWidgets static libraries"

# This is to avoid " Error: Unable to initialize GTK+, is DISPLAY set properly?" 
# when building over SSH without X11 Forwarding
# export DISPLAY=:0.0

# This will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuildConsole

# Check if wx-config exists in WX_BUILD_DIR
if [ -L "${WX_BUILD_DIR}/wx-config" ]; then
    echo "wx-config already exists in ${WX_BUILD_DIR}. Skipping wxbuild."
else
    echo "Using wxWidgets sources in $WX_ROOT"
    make WXSTATIC=1 NOGUI=1 $FUSE3_MAKE_FLAG wxbuild || exit 1
    ln -s $WX_BUILD_DIR/lib  $WX_BUILD_DIR/lib64
fi

rm -rf "$PARENTDIR/VeraCrypt_Setup/Console"
make WXSTATIC=1 NOGUI=1 $FUSE3_MAKE_FLAG clean 				|| exit 1
make WXSTATIC=1 NOGUI=1 $FUSE3_MAKE_FLAG 					|| exit 1
make WXSTATIC=1 NOGUI=1 $FUSE3_MAKE_FLAG install DESTDIR="$PARENTDIR/VeraCrypt_Setup/Console"	|| exit 1

echo "Creating VeraCrypt RPM packages "

# -DCPACK_RPM_PACKAGE_DEBUG=TRUE for debugging cpack RPM
# -DCPACK_RPM_PACKAGE_DEBUG=TRUE for debugging cpack RPM

# remove old packages
rm -rf $PARENTDIR/VeraCrypt_Packaging

mkdir -p $PARENTDIR/VeraCrypt_Packaging/GUI
mkdir -p $PARENTDIR/VeraCrypt_Packaging/Console

# wxWidgets was built using native GTK version
cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging/GUI -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/GUI" -DNOGUI=FALSE $FUSE3_CMAKE_FLAG || exit 1
cpack --config $PARENTDIR/VeraCrypt_Packaging/GUI/CPackConfig.cmake || exit 1
cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging/Console -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/Console" -DNOGUI=TRUE $FUSE3_CMAKE_FLAG || exit 1
cpack --config $PARENTDIR/VeraCrypt_Packaging/Console/CPackConfig.cmake|| exit 1
