# OpenWrt packaging

This directory contains the canonical OpenWrt package template and local test
configuration for building VeraCrypt console-only with the OpenWrt SDK.
It is a maintainer build-and-test harness for the VeraCrypt working tree, not
an OpenWrt packages-feed submission recipe.

The current supported target is `x86/64`, matching the QEMU runtime smoke test.
The build uses:

- OpenWrt 24.10.6 x86/64 SDK by default
- musl through the OpenWrt toolchain
- `NOGUI=1`
- `WITHFUSE3=1`
- `WXSTATIC=1`
- wxWidgets 3.2.10 built as static wxBase
- `NOTEST=1` during cross compilation
- `NOSTRIP=1`, with OpenWrt package stripping disabled for maintainer
  diagnostics

The package installs only:

- `/usr/bin/veracrypt`
- `/sbin/mount.veracrypt`
- `/usr/share/licenses/veracrypt/License.txt`

`mount.veracrypt` uses a Bash shebang, so the OpenWrt package declares `bash`
as a runtime dependency.

## Build

From the VeraCrypt checkout root:

```sh
src/Build/build_veracrypt_openwrt.sh
```

The script downloads and verifies the OpenWrt SDK against a pinned SHA-256 for
the supported release/target, downloads and verifies wxWidgets 3.2.10, installs
the required OpenWrt feeds, renders
`package/utils/veracrypt/Makefile` inside the SDK, builds the `.ipk`, and
also builds the local userland `bash`, `fuse3`, `util-linux`, and `lvm2` feed
packages used by the QEMU runtime test. Kernel modules for the stock OpenWrt
image are resolved by the test from the official OpenWrt kmod feed for the
selected release and target.

Default output location:

```text
../openwrt-veracrypt/openwrt-sdk-24.10.6-x86-64_gcc-13.3.0_musl.Linux-x86_64/bin/packages/x86_64/base/veracrypt_<version>-r1_x86_64.ipk
```

Useful options:

```sh
src/Build/build_veracrypt_openwrt.sh --fresh-sdk
src/Build/build_veracrypt_openwrt.sh --work-dir /tmp/veracrypt-openwrt
src/Build/build_veracrypt_openwrt.sh --sdk-dir /path/to/openwrt-sdk
src/Build/build_veracrypt_openwrt.sh --sdk-url URL --sdk-sha256 HASH
src/Build/build_veracrypt_openwrt.sh --wx-version 3.2.10
```

Custom SDK URLs or unsupported OpenWrt release/target combinations must pass
`--sdk-sha256`; the build script does not trust an unsigned `sha256sums` file as
the sole integrity source for SDK archives.

If the host only has `mawk`, the build script downloads and builds GNU awk
locally under the OpenWrt work directory because OpenWrt feed scripts require
GNU awk behavior on some hosts.

## QEMU Runtime Test

Install or provide `qemu-system-x86_64`. On Debian/Ubuntu hosts:

```sh
sudo apt install qemu-system-x86
```

Then run:

```sh
python3 src/Build/test_veracrypt_openwrt_qemu.py \
  --ipk ../openwrt-veracrypt/openwrt-sdk-24.10.6-x86-64_gcc-13.3.0_musl.Linux-x86_64/bin/packages/x86_64/base/veracrypt_<version>-r1_x86_64.ipk
```

The test script downloads and verifies the matching OpenWrt x86/64 ext4 image,
boots it with QEMU user networking, waits for OpenWrt network init to settle,
gets a DHCP lease on `br-lan` or `eth0`, resolves the needed dependency closure
from local SDK `.ipk` control metadata plus the official OpenWrt kmod feed,
serves those packages to the guest, and installs them with `opkg`. It then runs:

```sh
veracrypt --text --version
veracrypt --text --test
```

By default it also creates a 16 MiB AES/SHA-512 test container, opens it with
`--filesystem=none`, verifies it appears in `veracrypt --text --list`, and
unmounts it. Use `--skip-container` to run only the package install, version,
and algorithm self-test path.

If QEMU was extracted locally instead of installed system-wide, pass the binary
and firmware directory explicitly:

```sh
LD_LIBRARY_PATH=/path/to/qemu-libs \
python3 src/Build/test_veracrypt_openwrt_qemu.py \
  --qemu /path/to/qemu-system-x86_64 \
  --qemu-data-dir /path/to/pc-bios \
  --ipk /path/to/veracrypt_<version>-r1_x86_64.ipk
```

The runner defaults to one QEMU vCPU because TCG with multiple vCPUs can
intermittently trip x86 APIC timer startup in the stock OpenWrt image.
The runner does not require external package feed access from the guest; all
runtime packages are served over the host-to-guest QEMU user-networking link.
Local userland packages come from the SDK `bin/` directory, while stock-image
kmods are downloaded by the host from the official OpenWrt kmod feed and staged
locally. If the VeraCrypt `.ipk` is not below the SDK `bin/` directory, pass
`--package-bin-dir /path/to/sdk/bin`.

For custom images whose kernel does not match the official release feed, pass
`--kmod-feed-url` for the matching kmod feed, or `--local-kmods` to resolve
kmods from `--package-bin-dir`.

The test log is written to:

```text
../openwrt-veracrypt/openwrt-qemu-test.log
```

## Runtime Packages

The VeraCrypt package itself declares the direct userland dependencies using
OpenWrt package symbols:

- `libstdcpp`
- `libfuse3`
- `bash`

OpenWrt's FUSE3 recipe defines `Package/libfuse3` with ABI version `3`, so the
binary IPK and package-index metadata are emitted as `libfuse3-3` while still
providing `libfuse3`. The QEMU test installs the seed runtime support normally
needed for useful mounts using package-index names:

- `libfuse3-3`
- `fuse3-utils`
- `kmod-fuse`
- `kmod-loop`
- `lvm2`
- `kmod-dm`
- `losetup`
- `blkid`
- `mount-utils`
- `kmod-crypto-misc`

The test resolver also stages required transitive dependencies from package
metadata, such as `libdevmapper` when pulled by `lvm2`.

Filesystem-specific mounts also need the corresponding OpenWrt filesystem
kernel modules and tools. Smart-card and EMV keyfile support should install
`libpcsclite`, `pcscd`, and the appropriate reader driver such as `ccid`; these
are optional and are not part of the base package dependency set.
