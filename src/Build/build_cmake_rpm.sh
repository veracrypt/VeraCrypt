#!/bin/sh
#
# Copyright (c) 2013-2026 AM Crypto
# Governed by the Apache License 2.0 the full text of which is contained
# in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

# Errors should cause script to exit
set -e

# Keep staged RPM payload permissions independent of the caller's umask.
umask 022

# Absolute path to this script
export SCRIPT=$(readlink -f "$0")
# Absolute path this script is in
export SCRIPTPATH=$(dirname "$SCRIPT")
# Source directory which contains the Makefile
export SOURCEPATH=$(readlink -f "$SCRIPTPATH/..")
# Directory where the VeraCrypt has been checked out
export PARENTDIR=$(readlink -f "$SCRIPTPATH/../../..")

# Compute and export SOURCE_DATE_EPOCH so make/cmake/cpack/rpmbuild inherit
# the same value. Precedence: caller, git HEAD, Common/Tcdefs.h release date.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(sh "$SOURCEPATH/Build/Tools/source_date_epoch.sh" "$SOURCEPATH") || {
        echo "Error: SOURCE_DATE_EPOCH must be set, derivable from git, or derivable from Common/Tcdefs.h release date" >&2
        exit 1
    }
fi
case "$SOURCE_DATE_EPOCH" in
    ''|*[!0-9]*)
        echo "Error: SOURCE_DATE_EPOCH must be a non-negative Unix timestamp" >&2
        exit 1
        ;;
esac
export SOURCE_DATE_EPOCH

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
    if [ -d "$WX_BUILD_DIR/lib" ] && [ ! -e "$WX_BUILD_DIR/lib64" ]; then
        ln -s "$WX_BUILD_DIR/lib" "$WX_BUILD_DIR/lib64"
    fi
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

# Pin the RPM header BuildTime/BuildHost on rpm versions that predate the
# SOURCE_DATE_EPOCH/_buildhost macros (CentOS/RHEL <= 7, rpm < 4.14). A tiny
# libc-interposition shim is LD_PRELOAD'ed onto cpack's rpmbuild child; modern
# rpm sets the same values through its own macros (see Build/CMakeLists.txt), so
# the shim only matters where those macros do not exist. Payload mtimes/modes
# are handled separately by the install(SCRIPT) staging clamp.
#
# The shim is strictly optional: build it and use it only if it compiles and
# loads without emitting anything on stderr, otherwise package without it. A
# shim that failed to load would make ld.so print to stderr, which rpm's
# check-buildroot brp script captures and turns into a fatal %install error, so
# we never enable a shim we have not verified.
RPM_REPRO_SHIM=""
_shim_src="$SOURCEPATH/Build/Tools/repro_buildstamp.c"
_shim_so="$PARENTDIR/VeraCrypt_Packaging/repro_buildstamp.so"
_cc="${CC:-cc}"
if command -v "$_cc" >/dev/null 2>&1 &&
    "$_cc" -shared -fPIC -O2 -o "$_shim_so" "$_shim_src" -ldl 2>/dev/null &&
    [ -z "$(LD_PRELOAD="$_shim_so" /bin/sh -c : 2>&1)" ]; then
    RPM_REPRO_SHIM="$_shim_so"
    echo "Reproducible RPM: build-stamp shim enabled ($_shim_so)"
else
    echo "Reproducible RPM: build-stamp shim unavailable; header BuildTime/BuildHost rely on rpm macros (rpm >= 4.14/4.18)" >&2
fi

# Run cpack with the build-stamp shim preloaded when it is available.
run_cpack() {
    if [ -n "$RPM_REPRO_SHIM" ]; then
        LD_PRELOAD="$RPM_REPRO_SHIM" cpack "$@"
    else
        cpack "$@"
    fi
}

# wxWidgets was built using native GTK version
cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging/GUI -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/GUI" -DNOGUI=FALSE -DSOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH $FUSE3_CMAKE_FLAG || exit 1
run_cpack --config $PARENTDIR/VeraCrypt_Packaging/GUI/CPackConfig.cmake || exit 1
cmake -H$SCRIPTPATH -B$PARENTDIR/VeraCrypt_Packaging/Console -DVERACRYPT_BUILD_DIR="$PARENTDIR/VeraCrypt_Setup/Console" -DNOGUI=TRUE -DSOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH $FUSE3_CMAKE_FLAG || exit 1
run_cpack --config $PARENTDIR/VeraCrypt_Packaging/Console/CPackConfig.cmake || exit 1
