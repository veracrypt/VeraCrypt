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

# Make sure only root can run our script
if [ "$(id -u)" != "0" ]; then
   echo "VeraCrypt must be built by root" 1>&2
   exit 1
fi

# Check if wxWidgets-3.2.5 exists in PARENTDIR; if not, use /tmp
if [ ! -d "$PARENTDIR/wxWidgets-3.2.5" ]; then
    export PARENTDIR="/tmp"
fi

# The sources of wxWidgets 3.2.5 must be extracted to the parent directory
export WX_ROOT=$PARENTDIR/wxWidgets-3.2.5

# Exit with error if wxWidgets is not found
if [ ! -d "$WX_ROOT" ]; then
    echo "Error: wxWidgets-3.2.5 not found in either the default PARENTDIR or /tmp. Exiting."
    exit 1
fi

echo "Using wxWidgets sources in $WX_ROOT"

cd $SOURCEPATH

echo "Building GUI version of VeraCrypt"

# this will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuildGui

# Check if wx-config exists in WX_BUILD_DIR
if [ -L "${WX_BUILD_DIR}/wx-config" ]; then
    echo "wx-config already exists in ${WX_BUILD_DIR}. Skipping wxbuild."
else
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
    gmake WXSTATIC=1 NOGUI=1 wxbuild || exit 1
fi
gmake WXSTATIC=1 NOGUI=1 clean || exit 1
gmake WXSTATIC=1 NOGUI=1 || exit 1
gmake WXSTATIC=1 NOGUI=1 package || exit 1
