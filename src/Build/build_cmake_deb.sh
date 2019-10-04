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

cd $SOURCEPATH

echo "Building GUI version of VeraCrypt for DEB using system wxWidgets"
make clean 	|| exit 1
make 		|| exit 1
make install DESTDIR="$PARENTDIR/VeraCrypt_Setup/GUI"	|| exit 1

echo "Building console version of VeraCrypt for DEB using system wxWidgets"
# This is to avoid " Error: Unable to initialize GTK+, is DISPLAY set properly?" 
# when building over SSH without X11 Forwarding
# export DISPLAY=:0.0

make NOGUI=1 clean 	|| exit 1
make NOGUI=1 		|| exit 1
make NOGUI=1 install DESTDIR="$PARENTDIR/VeraCrypt_Setup/Console"	|| exit 1

echo "Creating VeraCrypt DEB packages"
# -DCPACK_RPM_PACKAGE_DEBUG=TRUE for debugging cpack DEB
# -DCPACK_RPM_PACKAGE_DEBUG=TRUE for debugging cpack DEB

mkdir $PARENTDIR/VeraCrypt_Packaging

cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/GUI" -DNOGUI=FALSE || exit 1
cpack --config $PARENTDIR/VeraCrypt_Packaging/CPackConfig.cmake || exit 1

cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/Console" -DNOGUI=TRUE || exit 1
cpack --config $PARENTDIR/VeraCrypt_Packaging/CPackConfig.cmake	|| exit 1