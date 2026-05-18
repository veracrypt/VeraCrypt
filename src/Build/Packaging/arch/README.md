# Arch Linux packaging

This directory contains two Arch Linux build paths:

- `PKGBUILD` packages the current VeraCrypt checkout without downloading
  sources. Use this for in-tree builds before a release source archive is
  published.
- `PKGBUILD.release` packages the official release source archive. Use this as
  the basis for clean chroot builds and downstream Arch packaging after the
  release archive is published. It is generated from `PKGBUILD.release.in` and
  is intentionally not committed.

To build and install a package from the current checkout:

```sh
cd src/Build/Packaging/arch
makepkg -si
```

The package build uses VeraCrypt's normal GNU Make build, stages files through
`make install DESTDIR=...`, omits the generic self-uninstaller and
AppImage-specific staging files, installs the HTML documentation for offline
Help, installs the mount helper under `/usr/bin` for Arch's merged `/usr` layout,
and places the license under `/usr/share/licenses/veracrypt`. This is deliberate:
`mount(8)` looks for `/sbin/mount.<type>` helpers, and Arch's `/sbin` symlink to
`/usr/bin` makes `/usr/bin/mount.veracrypt` resolve through that compatibility
path while keeping package-owned binaries in `/usr/bin`.

The in-tree `PKGBUILD` intentionally uses the checked-out source tree, so it is
not the file to submit to the AUR or other package repositories and is not
suitable for static PKGBUILD parsers or clean chroot builds that only copy
declared `source=()` inputs. Run static packaging tools against the generated
`PKGBUILD.release` instead. It runs `make clean` before each build and writes
normal VeraCrypt build artifacts into the checkout. The `clean` target in this
directory removes only Arch packaging artifacts and the generated
`PKGBUILD.release`; it does not clean the upstream VeraCrypt build tree or
`Setup/Linux/usr`.

The PKGBUILDs run VeraCrypt's self-test from `check()`. Use `makepkg --nocheck`
only for cross or emulated builds where the target binary cannot run.

For a release build, wait until the official source archive exists, then run:

```sh
make pkgbuild-release
```

Replace only the first temporary `SKIP` checksum in `PKGBUILD.release` with the
published SHA-512 checksum for the source archive. Leave the `.sig` checksum as
`SKIP`; makepkg uses it for PGP verification. Coordinate changes with the
official Arch package maintainer when targeting Arch's official repositories. If
copying `PKGBUILD.release` to an AUR-style packaging repository, regenerate
`.SRCINFO`:

```sh
makepkg --printsrcinfo > .SRCINFO
```

Use `PKGBUILD.release` for reproducible-build checks; byte-identical packages
should be built from the same release archive rather than a live checkout.
