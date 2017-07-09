#!/bin/sh
V="$(mount | grep veracrypt_aux_mnt)"
[ "$V" ] && echo Error: All volumes must be dismounted first. && exit 1

rm -f /usr/bin/veracrypt
rm -f /usr/share/applications/veracrypt.desktop
rm -f /usr/share/pixmaps/veracrypt.xpm
rm -fr /usr/share/veracrypt

echo VeraCrypt uninstalled.
rm -f /usr/bin/veracrypt-uninstall.sh
