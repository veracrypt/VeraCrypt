#!/usr/bin/env bash

#
# Copyright (c) 2013-2024 IDRIX
# Governed by the Apache License 2.0 the full text of which is contained
# in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

# Exit immediately if a command exits with a non-zero status
set -e

# Absolute path this script is in
SCRIPTPATH=$(cd "$(dirname "$0")" && pwd)
# source directory which contains the Makefile
SOURCEPATH=$(cd "$(dirname "$SCRIPTPATH/../.")" && pwd)
# directory where the VeraCrypt project has been checked out
PARENTDIR=$(cd "$(dirname "$SCRIPTPATH/../../../.")" && pwd)

# Default wxWidgets version
DEFAULT_WX_VERSION="3.2.5"
WX_VERSION="$DEFAULT_WX_VERSION"

# Initialize flags
brew=false
package=false
fuset=false
local_build=false

# Function to display usage information
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -b           Use Homebrew to build with precompiled packages"
    echo "  -p           Create a package after building"
    echo "  -f           Build with FUSE-T support"
    echo "  -l           Use local wxWidgets and disable universal binaries"
    echo "  -v <version> Specify wxWidgets version (default: $DEFAULT_WX_VERSION)"
    echo "  -h           Display this help message"
    exit 1
}

# Parse command-line options
while getopts "bpflv:h" flag
do
    case "${flag}" in
        b) brew=true;;
        p) package=true;;
        f) fuset=true;;
        l) local_build=true;;
        v)
            if [ -z "$OPTARG" ]; then
                echo "Error: -v requires a version argument."
                usage
            fi
            WX_VERSION=${OPTARG}
            ;;
        h) usage;;
        *) usage;;
    esac
done

export VC_OSX_FUSET=$([ "$fuset" = true ] && echo 1 || echo 0)

if [ "$fuset" = true ]; then
    echo "Building VeraCrypt with FUSE-T support"
else
    echo "Building VeraCrypt with MacFUSE support"
fi

if [ "$brew" = true ]; then
    if ! command -v brew &> /dev/null; then
        echo "Homebrew is not installed. Please install Homebrew or run without the -b flag."
        exit 1
    fi

    export VC_OSX_SDK=$(xcrun --show-sdk-version) # use the latest version installed, this might fail
    export VC_OSX_TARGET=${VC_OSX_SDK}
    echo "Using MacOSX SDK $VC_OSX_SDK with target set to $VC_OSX_TARGET"
    cd "$SOURCEPATH"

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
    make clean
    make
    if [ "$package" = true ]; then
        make package
    fi
    exit 0
fi

if [ "$local_build" = true ]; then
    echo "Building VeraCrypt with local wxWidgets support and no universal binary"
    export LOCAL_DEVELOPMENT_BUILD=true
fi

# Check the condition of wxBuildConsole and wxWidgets-$WX_VERSION in the original PARENTDIR
if [ -d "$PARENTDIR/wxBuildConsole" ]; then
    echo "Using existing PARENTDIR: $PARENTDIR, wxBuildConsole is present."
elif [ -d "$PARENTDIR/wxWidgets-$WX_VERSION" ]; then
    echo "Using existing PARENTDIR: $PARENTDIR, wxWidgets-$WX_VERSION is present."
else
    # Change PARENTDIR to /tmp and check conditions again
    export PARENTDIR="/tmp"
    if [ -d "$PARENTDIR/wxBuildConsole" ]; then
        echo "Switched to PARENTDIR: /tmp, wxBuildConsole is present in /tmp."
    elif [ -d "$PARENTDIR/wxWidgets-$WX_VERSION" ]; then
        echo "Switched to PARENTDIR: /tmp, wxWidgets-$WX_VERSION is present in /tmp."
    else
        echo "Error: Neither wxBuildConsole nor wxWidgets-$WX_VERSION found in /tmp. Exiting."
        exit 1
    fi
fi

# The sources of wxWidgets $WX_VERSION must be extracted to the parent directory
export WX_ROOT="$PARENTDIR/wxWidgets-$WX_VERSION"

# this will be the temporary wxWidgets directory
export WX_BUILD_DIR="$PARENTDIR/wxBuild-$WX_VERSION"

# define the SDK version to use and OSX minimum target. We target 12 by default
export VC_OSX_TARGET=12
export VC_OSX_SDK=$(xcrun --show-sdk-version) #use the latest version installed
echo "Using MacOSX SDK $VC_OSX_SDK with target set to $VC_OSX_TARGET"

cd "$SOURCEPATH"

echo "Building VeraCrypt"
# Check if wx-config exists in WX_BUILD_DIR
if [ -L "${WX_BUILD_DIR}/wx-config" ]; then
    echo "wx-config already exists in ${WX_BUILD_DIR}. Skipping wxbuild."
else
    echo "Using wxWidgets sources in $WX_ROOT"
    make WXSTATIC=FULL wxbuild
fi
make WXSTATIC=FULL clean
make WXSTATIC=FULL
if [ "$package" = true ]; then
    make WXSTATIC=FULL package
fi

echo "VeraCrypt build completed successfully."
