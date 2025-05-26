#!/bin/sh
V="$(mount | grep veracrypt_aux_mnt)"
[ "$V" ] && echo "Error: All volumes must be dismounted first." 1>&2 && exit 1

removal_failed() {
	echo "Error: File removal failed, please run the script with elevated privileges." 1>&2 && exit 1
}

rm -f /usr/bin/veracrypt || removal_failed
rm -f /usr/local/share/applications/veracrypt.desktop || removal_failed
rm -f /usr/local/share/pixmaps/veracrypt.xpm || removal_failed
rm -f /usr/local/share/mime/packages/veracrypt.xml || removal_failed
rm -fr /usr/share/veracrypt || removal_failed
rm -fr /usr/share/doc/veracrypt || removal_failed
rm -f /usr/local/share/icons/hicolor/scalable/apps/veracrypt.svg || removal_failed
rm -f /usr/local/share/icons/hicolor/symbolic/apps/veracrypt-symbolic.svg || removal_failed
for res in 16 22 24 32 48 64 256 512 1024; do \
		rm -f /usr/share/icons/hicolor/${res}x${res}/apps/veracrypt.png || removal_failed ;\
done

rm -f /usr/bin/veracrypt-uninstall.sh || removal_failed
update-mime-database /usr/local/share/mime >/dev/null 2>&1
update-desktop-database -q

echo VeraCrypt uninstalled.
