#!/bin/sh
V="$(mount | grep veracrypt_aux_mnt)"
[ "$V" ] && echo "Error: All volumes must be dismounted first." 1>&2 && exit 1

removal_failed() {
	echo "Error: File removal failed, please run the script with elevated privileges." 1>&2 && exit 1
}

rm -f /usr/bin/veracrypt || removal_failed
rm -f /usr/share/applications/veracrypt.desktop || removal_failed
rm -f /usr/share/pixmaps/veracrypt.xpm || removal_failed
rm -f /usr/share/mime/packages/veracrypt.xml || removal_failed
rm -fr /usr/share/veracrypt || removal_failed
rm -fr /usr/share/doc/veracrypt || removal_failed
rm -f /usr/bin/veracrypt-uninstall.sh || removal_failed
update-mime-database /usr/share/mime >/dev/null 2>&1
update-desktop-database -q

echo VeraCrypt uninstalled.
