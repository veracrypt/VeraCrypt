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

# the sources of wxWidgets 3.0.2 must be extracted to the parent directory
export WX_ROOT=$PARENTDIR/wxWidgets-3.0.2
echo "Using wxWidgets sources in $WX_ROOT"

# this will be the temporary wxWidgets directory
export WX_BUILD_DIR=$PARENTDIR/wxBuild

cd $SOURCEPATH

echo "Building GUI version of VeraCrypt"
make WXSTATIC=1 wxbuild && make WXSTATIC=1 clean && make WXSTATIC=1

echo "Building console version of VeraCrypt"
make WXSTATIC=1 NOGUI=1 wxbuild && make WXSTATIC=1 NOGUI=1 clean && make WXSTATIC=1 NOGUI=1
