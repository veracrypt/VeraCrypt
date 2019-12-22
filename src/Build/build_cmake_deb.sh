#!/bin/sh

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

# The sources of wxWidgets 3.0.4 must be extracted to the parent directory
export WX_ROOT=$PARENTDIR/wxWidgets-3.0.4
echo "Using wxWidgets sources in $WX_ROOT"

cd $SOURCEPATH

if [ "$#" = "1" ] && [ "$1" = "WXSTATIC" ]
then
echo "Building GUI version of VeraCrypt for DEB using wxWidgets static libraries"

# This will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuildGUI

# To build wxWidgets without GUI
make WXSTATIC=1 wxbuild 	|| exit 1
make WXSTATIC=1 clean 		|| exit 1
make WXSTATIC=1  			|| exit 1
make WXSTATIC=1 install DESTDIR="$PARENTDIR/VeraCrypt_Setup/GUI"	|| exit 1

else

echo "Building GUI version of VeraCrypt for DEB using system wxWidgets"
make clean 	|| exit 1
make 		|| exit 1
make install DESTDIR="$PARENTDIR/VeraCrypt_Setup/GUI"	|| exit 1

fi

echo "Building console version of VeraCrypt for DEB using wxWidgets static libraries"

# This is to avoid " Error: Unable to initialize GTK+, is DISPLAY set properly?" 
# when building over SSH without X11 Forwarding
# export DISPLAY=:0.0

# This will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuildConsole

# To build wxWidgets without GUI
make WXSTATIC=1 NOGUI=1 wxbuild 	|| exit 1
make WXSTATIC=1 NOGUI=1 clean 		|| exit 1
make WXSTATIC=1 NOGUI=1 			|| exit 1
make WXSTATIC=1 NOGUI=1 install DESTDIR="$PARENTDIR/VeraCrypt_Setup/Console"	|| exit 1

echo "Creating VeraCrypt DEB packages"

# -DCPACK_RPM_PACKAGE_DEBUG=TRUE for debugging cpack DEB
# -DCPACK_RPM_PACKAGE_DEBUG=TRUE for debugging cpack DEB

mkdir -p $PARENTDIR/VeraCrypt_Packaging/GUI
mkdir -p $PARENTDIR/VeraCrypt_Packaging/Console

cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging/GUI -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/GUI" -DNOGUI=FALSE || exit 1
cpack --config $PARENTDIR/VeraCrypt_Packaging/GUI/CPackConfig.cmake || exit 1
cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging/Console -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/Console" -DNOGUI=TRUE || exit 1
cpack --config $PARENTDIR/VeraCrypt_Packaging/Console/CPackConfig.cmake	|| exit 1
