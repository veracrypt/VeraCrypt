#!/bin/sh
#
# Copyright (c) 2013-2024 IDRIX
# Governed by the Apache License 2.0 the full text of which is contained
# in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

# Absolute path to this script
SCRIPT=$(readlink -f "$0")
# Absolute path this script is in
SCRIPTPATH=$(dirname "$SCRIPT")
# source directory which contains the Makefile
SOURCEPATH=$(readlink -f "$SCRIPTPATH/..")
# directory where the VeraCrypt has been checked out
PARENTDIR=$(readlink -f "$SCRIPTPATH/../../..")

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

echo "Building GUI version of VeraCrypt"

# this will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuildGui

# Check if wx-config exists in WX_BUILD_DIR
if [ -L "${WX_BUILD_DIR}/wx-config" ]; then
    echo "wx-config already exists in ${WX_BUILD_DIR}. Skipping wxbuild."
else
    echo "Using wxWidgets sources in $WX_ROOT"
    gmake WXSTATIC=1 wxbuild || exit 1
fi

gmake WXSTATIC=1 clean || exit 1
gmake WXSTATIC=1 || exit 1
gmake WXSTATIC=1 package || exit 1

echo "Building console version of VeraCrypt"

# this will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuildConsole

# Check if wx-config exists in WX_BUILD_DIR
if [ -L "${WX_BUILD_DIR}/wx-config" ]; then
    echo "wx-config already exists in ${WX_BUILD_DIR}. Skipping wxbuild."
else
   echo "Using wxWidgets sources in $WX_ROOT"
    gmake WXSTATIC=1 NOGUI=1 wxbuild || exit 1
fi
gmake WXSTATIC=1 NOGUI=1 clean || exit 1
gmake WXSTATIC=1 NOGUI=1 || exit 1
gmake WXSTATIC=1 NOGUI=1 package || exit 1
