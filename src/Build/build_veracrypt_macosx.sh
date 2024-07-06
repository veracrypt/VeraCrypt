#!/usr/bin/env bash

#
# Copyright (c) 2013-2024 IDRIX
# Governed by the Apache License 2.0 the full text of which is contained
# in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

# Absolute path this script is in
SCRIPTPATH=$(cd "$(dirname "$0")"; pwd)
# source directory which contains the Makefile
SOURCEPATH=$(cd "$(dirname "$SCRIPTPATH/../.")"; pwd)
# directory where the VeraCrypt project has been checked out
PARENTDIR=$(cd "$(dirname "$SCRIPTPATH/../../../.")"; pwd)

while getopts bpf flag
do
    case "${flag}" in
        b) brew=true;;
        p) package=true;;
        f) fuset=true;;
    esac
done

export VC_OSX_FUSET=0

if [ -n "$fuset" ]; then
    echo "Building VeraCrypt with FUSE-T support"
    VC_OSX_FUSET=1
else
    echo "Building VeraCrypt with MacFUSE support"
fi

if [ -n "$brew" ]; then
    export VC_OSX_SDK=$(xcrun --show-sdk-version) #use the latest version installed, this might fail
    export VC_OSX_TARGET=${VC_OSX_SDK}
    echo "Using MacOSX SDK $VC_OSX_SDK with target set to $VC_OSX_TARGET"
    cd $SOURCEPATH

    echo "Building VeraCrypt with precompiled homebrew packages"
    cellar=$(brew --cellar "wxwidgets")
    version=$(brew list --versions "wxwidgets" | head -1 | awk '{print $2}')
    export WX_BUILD_DIR="$cellar/$version/bin"
    # skip signing and build only for local arch
    export LOCAL_DEVELOPMENT_BUILD=true
    # set the correct CPU arch for Makefile
    export CPU_ARCH=$(uname -m)
    export AS=$(which yasm)
    export COMPILE_ASM=$( if [[ "$CPU_ARCH" != "arm64" ]]; then echo true; else echo false; fi )
    make clean && make
    if [ -n "$package" ]; then
        make package
    fi
    exit 0
fi

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

# this will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuild-3.2.5

# define the SDK version to use and OSX minimum target. We target 12 by default
export VC_OSX_TARGET=12
export VC_OSX_SDK=$(xcrun --show-sdk-version) #use the latest version installed
echo "Using MacOSX SDK $VC_OSX_SDK with target set to $VC_OSX_TARGET"

cd $SOURCEPATH

echo "Building VeraCrypt"
# Check if wx-config exists in WX_BUILD_DIR
if [ -L "${WX_BUILD_DIR}/wx-config" ]; then
    echo "wx-config already exists in ${WX_BUILD_DIR}. Skipping wxbuild."
else
    echo "Using wxWidgets sources in $WX_ROOT"
    make WXSTATIC=FULL wxbuild || exit 1
fi
make WXSTATIC=FULL clean || exit 1
make WXSTATIC=FULL || exit 1
make WXSTATIC=FULL package || exit 1
