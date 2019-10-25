#
# Copyright (c) 2013-2017 IDRIX
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

# the sources of wxWidgets 3.1.2 must be extracted to the parent directory
export WX_ROOT=$PARENTDIR/wxWidgets-3.1.2
echo "Using wxWidgets sources in $WX_ROOT"
# this will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuild

# define the SDK version to use. We use 10.7 by default
export VC_OSX_TARGET=10.7
export VC_OSX_SDK=10.9
echo "Using MacOSX SDK $VC_OSX_TARGET"


cd $SOURCEPATH

echo "Building VeraCrypt"
make WXSTATIC=FULL wxbuild && make WXSTATIC=FULL clean && make WXSTATIC=FULL && make WXSTATIC=FULL package

# Uncomment below and comment line above to reuse existing wxWidgets build
# make WXSTATIC=FULL clean && make WXSTATIC=FULL && make WXSTATIC=FULL package
