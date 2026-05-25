#!/bin/sh
#
# Copyright (c) 2026 AM Crypto
# Governed by the Apache License 2.0 the full text of which is contained
# in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

set -eu
umask 022

OPENWRT_VERSION=24.10.6
OPENWRT_TARGET=x86/64
WX_VERSION=3.2.10
WX_URL=
WX_SHA256=d66e929569947a4a5920699539089a9bda83a93e5f4917fb313a61f0c344b896
SDK_URL=
SDK_SHA256=
SDK_DIR=
FRESH_SDK=0

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
REPOROOT=$(readlink -f "$SCRIPTPATH/../..")
SOURCEPATH="$REPOROOT/src"
PARENTDIR=$(readlink -f "$SCRIPTPATH/../../..")
WORK_DIR="$PARENTDIR/openwrt-veracrypt"
JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)

GAWK_VERSION=5.3.2
GAWK_URL="https://ftp.gnu.org/gnu/gawk/gawk-$GAWK_VERSION.tar.xz"
GAWK_SHA256=f8c3486509de705192138b00ef2c00bbbdd0e84c30d5c07d23fc73a9dc4cc9cc

usage() {
	cat <<EOF
Usage: $(basename "$0") [options]

Build the VeraCrypt console-only OpenWrt package with the OpenWrt SDK.

Options:
  --openwrt-version VERSION   OpenWrt release to use (default: $OPENWRT_VERSION)
  --target TARGET             OpenWrt target/subtarget (default: $OPENWRT_TARGET)
  --work-dir DIR              Download/build workspace (default: $WORK_DIR)
  --sdk-url URL               SDK archive URL (auto-detected for x86/64)
  --sdk-sha256 HASH           SDK archive SHA-256 (required for custom SDKs)
  --sdk-dir DIR               Use an already extracted SDK directory
  --fresh-sdk                 Re-extract the SDK before building
  --wx-version VERSION        wxWidgets version (default: $WX_VERSION)
  --wx-url URL                wxWidgets source archive URL
  --wx-sha256 HASH            wxWidgets source archive SHA-256
  -j, --jobs N                Parallel make jobs (default: host CPU count)
  -h, --help                  Show this help

Only x86/64 is currently wired because it is the QEMU smoke-test target.
EOF
}

die() {
	echo "Error: $*" >&2
	exit 1
}

need_tool() {
	command -v "$1" >/dev/null 2>&1 || die "Required tool '$1' was not found"
}

require_option_arg() {
	[ $# -ge 2 ] || die "Option $1 requires an argument"
}

download_file() {
	url=$1
	out=$2
	expected_sha=$3
	tmp="$out.tmp.$$"

	mkdir -p "$(dirname "$out")"
	if [ -f "$out" ]; then
		if [ -z "$expected_sha" ]; then
			return
		fi

		actual_sha=$(sha256sum "$out" | awk '{print $1}')
		if [ "$actual_sha" = "$expected_sha" ]; then
			return
		fi

		echo "Checksum mismatch for existing $out; re-downloading" >&2
		rm -f "$out"
	fi

	rm -f "$tmp"
	echo "Downloading $url"
	if ! wget -O "$tmp" "$url"; then
		rm -f "$tmp"
		die "Download failed: $url"
	fi

	if [ -n "$expected_sha" ]; then
		actual_sha=$(sha256sum "$tmp" | awk '{print $1}')
		if [ "$actual_sha" != "$expected_sha" ]; then
			rm -f "$tmp"
			die "SHA-256 mismatch for $out: expected $expected_sha, got $actual_sha"
		fi
	fi

	mv "$tmp" "$out"
}

pinned_sdk_sha256() {
	archive_name=$1

	case "$OPENWRT_VERSION:$OPENWRT_TARGET:$archive_name" in
		24.10.6:x86/64:openwrt-sdk-24.10.6-x86-64_gcc-13.3.0_musl.Linux-x86_64.tar.zst)
			printf '%s\n' "9e398ea7efc098e4a986f97efff595e32d08c615fe356bcb3d885d7ad3a39ac0"
			;;
	esac
}

target_defaults() {
	case "$OPENWRT_TARGET" in
		x86/64)
			OPENWRT_TARGET_SLUG=x86-64
			OPENWRT_CONFIG="$REPOROOT/src/Build/Packaging/openwrt/configs/x86_64-minimal.config"
			;;
		*)
			die "Unsupported target '$OPENWRT_TARGET'. Add a config under src/Build/Packaging/openwrt/configs first."
			;;
	esac
}

openwrt_base_url() {
	printf 'https://downloads.openwrt.org/releases/%s/targets/%s\n' "$OPENWRT_VERSION" "$OPENWRT_TARGET"
}

resolve_sdk() {
	if [ -n "$SDK_DIR" ]; then
		SDK_DIR=$(readlink -f "$SDK_DIR")
		[ -d "$SDK_DIR" ] || die "SDK directory does not exist: $SDK_DIR"
		return
	fi

	base_url=$(openwrt_base_url)

	mkdir -p "$WORK_DIR/downloads"
	if [ -z "$SDK_URL" ]; then
		index_file="$WORK_DIR/downloads/openwrt-$OPENWRT_VERSION-$OPENWRT_TARGET_SLUG-index.html"
		wget -q -O "$index_file" "$base_url/"
		sdk_archive=$(sed -n "s/.*href=\"\\(openwrt-sdk-$OPENWRT_VERSION-${OPENWRT_TARGET_SLUG}_[^\"]*\\.Linux-x86_64\\.tar\\.zst\\)\".*/\\1/p" "$index_file" | head -n 1)
		[ -n "$sdk_archive" ] || die "Could not find an SDK archive at $base_url/"
		SDK_URL="$base_url/$sdk_archive"
	else
		sdk_archive=$(basename "$SDK_URL")
	fi

	if [ -z "$SDK_SHA256" ]; then
		SDK_SHA256=$(pinned_sdk_sha256 "$sdk_archive")
	fi

	[ -n "$SDK_SHA256" ] || die "No trusted SDK SHA-256 is available for $sdk_archive; pass --sdk-sha256 for custom SDKs"

	SDK_ARCHIVE_PATH="$WORK_DIR/downloads/$sdk_archive"
	download_file "$SDK_URL" "$SDK_ARCHIVE_PATH" "$SDK_SHA256"

	sdk_top=$(zstd -dc "$SDK_ARCHIVE_PATH" | tar -tf - | sed -n '1{s,/.*,,;p;q;}')
	[ -n "$sdk_top" ] || die "Could not determine SDK archive top-level directory"
	SDK_DIR="$WORK_DIR/$sdk_top"

	if [ "$FRESH_SDK" = "1" ]; then
		rm -rf "$SDK_DIR"
	fi

	if [ ! -d "$SDK_DIR" ]; then
		echo "Extracting $SDK_ARCHIVE_PATH"
		zstd -dc "$SDK_ARCHIVE_PATH" | tar -xf - -C "$WORK_DIR"
	fi
}

ensure_gawk() {
	HOST_TOOLS="$WORK_DIR/host-tools"
	if command -v gawk >/dev/null 2>&1; then
		mkdir -p "$HOST_TOOLS/bin"
		ln -sf "$(command -v gawk)" "$HOST_TOOLS/bin/gawk"
		ln -sf "$(command -v gawk)" "$HOST_TOOLS/bin/awk"
		return
	fi

	if [ -x "$HOST_TOOLS/prefix/bin/gawk" ]; then
		mkdir -p "$HOST_TOOLS/bin"
		ln -sf ../prefix/bin/gawk "$HOST_TOOLS/bin/gawk"
		ln -sf ../prefix/bin/gawk "$HOST_TOOLS/bin/awk"
		return
	fi

	need_tool make
	if ! command -v gcc >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; then
		die "GNU awk is not installed and no C compiler was found to build it"
	fi

	mkdir -p "$HOST_TOOLS/src"
	gawk_archive="$HOST_TOOLS/src/gawk-$GAWK_VERSION.tar.xz"
	download_file "$GAWK_URL" "$gawk_archive" "$GAWK_SHA256"

	rm -rf "$HOST_TOOLS/src/gawk-$GAWK_VERSION"
	tar -xf "$gawk_archive" -C "$HOST_TOOLS/src"
	echo "Building GNU awk $GAWK_VERSION for OpenWrt feed scripts"
	(
		cd "$HOST_TOOLS/src/gawk-$GAWK_VERSION"
		./configure --prefix="$HOST_TOOLS/prefix" >/dev/null
		make -j "$JOBS" >/dev/null
		make install >/dev/null
	)
	mkdir -p "$HOST_TOOLS/bin"
	ln -sf ../prefix/bin/gawk "$HOST_TOOLS/bin/gawk"
	ln -sf ../prefix/bin/gawk "$HOST_TOOLS/bin/awk"
}

prepare_wxwidgets() {
	if [ -z "$WX_URL" ]; then
		WX_URL="https://github.com/wxWidgets/wxWidgets/releases/download/v$WX_VERSION/wxWidgets-$WX_VERSION.tar.bz2"
	fi

	wx_archive="$WORK_DIR/downloads/wxWidgets-$WX_VERSION.tar.bz2"
	WX_SOURCE_DIR="$WORK_DIR/sources/wxWidgets-$WX_VERSION"
	download_file "$WX_URL" "$wx_archive" "$WX_SHA256"

	if [ ! -f "$WX_SOURCE_DIR/configure" ]; then
		rm -rf "$WX_SOURCE_DIR"
		mkdir -p "$WORK_DIR/sources"
		echo "Extracting $wx_archive"
		tar -xjf "$wx_archive" -C "$WORK_DIR/sources"
	fi
}

sed_escape() {
	printf '%s' "$1" | sed 's/[&|]/\\&/g'
}

render_package_makefile() {
	version=$(sed -n 's/^#define[[:space:]][[:space:]]*VERSION_STRING[[:space:]][[:space:]]*"\([^"]*\)".*/\1/p' "$SOURCEPATH/Common/Tcdefs.h" | head -n 1)
	[ -n "$version" ] || die "Could not determine VeraCrypt version from src/Common/Tcdefs.h"

	package_dir="$SDK_DIR/package/utils/veracrypt"
	template="$REPOROOT/src/Build/Packaging/openwrt/package/utils/veracrypt/Makefile.in"

	rm -rf "$package_dir"
	mkdir -p "$package_dir"
	sed \
		-e "s|@VERACRYPT_VERSION@|$(sed_escape "$version")|g" \
		-e "s|@VERACRYPT_SOURCE_DIR@|$(sed_escape "$REPOROOT")|g" \
		-e "s|@WXWIDGETS_VERSION@|$(sed_escape "$WX_VERSION")|g" \
		-e "s|@WXWIDGETS_SOURCE_DIR@|$(sed_escape "$WX_SOURCE_DIR")|g" \
		"$template" > "$package_dir/Makefile"

	VERACRYPT_VERSION=$version
}

configure_sdk() {
	[ -f "$OPENWRT_CONFIG" ] || die "Missing OpenWrt config seed: $OPENWRT_CONFIG"

	cp "$OPENWRT_CONFIG" "$SDK_DIR/.config"
	(
		cd "$SDK_DIR"
		if ! PATH="$HOST_TOOLS/bin:$PATH" ./scripts/feeds update packages base; then
			echo "Feed update failed; removing stale feed checkouts and retrying" >&2
			rm -rf feeds/base feeds/packages
			PATH="$HOST_TOOLS/bin:$PATH" ./scripts/feeds update packages base
		fi
		PATH="$HOST_TOOLS/bin:$PATH" ./scripts/feeds install fuse3 lvm2 util-linux pcsc-lite bash
		PATH="$HOST_TOOLS/bin:$PATH" make defconfig
	)
}

build_package() {
	(
		cd "$SDK_DIR"
		PATH="$HOST_TOOLS/bin:$PATH" make package/utils/veracrypt/clean V=s
		PATH="$HOST_TOOLS/bin:$PATH" make package/utils/veracrypt/compile V=s -j "$JOBS"
	)

	IPK_PATH=$(find "$SDK_DIR/bin/packages" "$SDK_DIR/bin/targets" -name "veracrypt_${VERACRYPT_VERSION}-*.ipk" 2>/dev/null | sort | tail -n 1)
	[ -n "$IPK_PATH" ] || die "Build completed but no VeraCrypt .ipk was found"
}

build_runtime_packages() {
	(
		cd "$SDK_DIR"
		for target in \
			package/feeds/packages/bash/compile \
			package/feeds/packages/fuse3/compile \
			package/feeds/base/util-linux/compile \
			package/feeds/packages/lvm2/compile
		do
			echo "Building OpenWrt runtime dependency: $target"
			PATH="$HOST_TOOLS/bin:$PATH" make "$target" V=s -j "$JOBS"
		done
	)
}

while [ $# -gt 0 ]; do
	case "$1" in
		--openwrt-version)
			require_option_arg "$@"
			OPENWRT_VERSION=$2
			shift 2
			;;
		--target)
			require_option_arg "$@"
			OPENWRT_TARGET=$2
			shift 2
			;;
		--work-dir)
			require_option_arg "$@"
			WORK_DIR=$(readlink -m "$2")
			shift 2
			;;
		--sdk-url)
			require_option_arg "$@"
			SDK_URL=$2
			shift 2
			;;
		--sdk-sha256)
			require_option_arg "$@"
			SDK_SHA256=$2
			shift 2
			;;
		--sdk-dir)
			require_option_arg "$@"
			SDK_DIR=$2
			shift 2
			;;
		--fresh-sdk)
			FRESH_SDK=1
			shift
			;;
		--wx-version)
			require_option_arg "$@"
			WX_VERSION=$2
			shift 2
			;;
		--wx-url)
			require_option_arg "$@"
			WX_URL=$2
			shift 2
			;;
		--wx-sha256)
			require_option_arg "$@"
			WX_SHA256=$2
			shift 2
			;;
		-j|--jobs)
			require_option_arg "$@"
			JOBS=$2
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			die "Unknown option: $1"
			;;
	esac
done

case "$JOBS" in
	''|*[!0-9]*)
		die "jobs must be a positive integer"
		;;
esac
[ "$JOBS" -gt 0 ] || die "jobs must be a positive integer"

need_tool awk
need_tool find
need_tool make
need_tool rsync
need_tool sed
need_tool sha256sum
need_tool tar
need_tool wget
need_tool yasm
need_tool zstd

mkdir -p "$WORK_DIR"
target_defaults
resolve_sdk
ensure_gawk
prepare_wxwidgets
render_package_makefile
configure_sdk
build_package
build_runtime_packages

echo
echo "OpenWrt release: $OPENWRT_VERSION $OPENWRT_TARGET"
if [ -n "$SDK_URL" ]; then
	echo "OpenWrt SDK: $SDK_URL"
else
	echo "OpenWrt SDK: existing directory supplied with --sdk-dir"
fi
echo "SDK directory: $SDK_DIR"
echo "wxWidgets: $WX_URL"
echo "VeraCrypt package: $IPK_PATH"
sha256sum "$IPK_PATH"
echo
echo "Run the QEMU runtime test with:"
echo "  python3 \"$SCRIPTPATH/test_veracrypt_openwrt_qemu.py\" --ipk \"$IPK_PATH\" --work-dir \"$WORK_DIR\""
