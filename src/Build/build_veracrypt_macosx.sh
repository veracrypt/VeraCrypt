#!/usr/bin/env bash

#
# Copyright (c) 2013-2019 IDRIX
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

while getopts bpr flag
do
    case "${flag}" in
        b) brew=true;;
        p) package=true;;
    esac
done

if [ -n "$brew" ]; then
    export VC_OSX_TARGET=10.9
    export VC_OSX_SDK=$(xcrun --show-sdk-version) #use the latest version installed, this might fail
    echo "Using MacOSX SDK $VC_OSX_SDK with target set to $VC_OSX_TARGET"
    cd $SOURCEPATH

    echo "Building VeraCrypt with precompiled homebrew packages"
    cellar=$(brew --cellar "wxwidgets")
    version=$(brew list --versions "wxwidgets" | head -1 | awk '{print $2}')
    export WX_BUILD_DIR="$cellar/$version/bin"
    export LOCAL_DEVELOPMENT_BUILD=true

    make clean && make
    if [ -n "$package" ]; then
        make package
    fi
    exit 0
fi

# the sources of wxWidgets 3.1.2 must be extracted to the parent directory (for night mode)
export WX_ROOT=$PARENTDIR/wxWidgets-3.2.2.1
echo "Using wxWidgets sources in $WX_ROOT"

# this will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuild-3.2.2.1

# define the SDK version to use and OSX minimum target. We target 10.9 by default
export VC_OSX_TARGET=12
export VC_OSX_SDK=13
echo "Using MacOSX SDK $VC_OSX_SDK with target set to $VC_OSX_TARGET"

cd $SOURCEPATH

echo "Building VeraCrypt"
make WXSTATIC=FULL wxbuild && make WXSTATIC=FULL clean && make WXSTATIC=FULL && make WXSTATIC=FULL package

# Uncomment below and comment line above to reuse existing wxWidgets build
# make WXSTATIC=FULL clean && make WXSTATIC=FULL && make WXSTATIC=FULL package

