#!/bin/bash

chmod -R go-w /Applications/VeraCrypt.app

# remove obsolete donation bank files from previous installs
rm -f \
    /Applications/VeraCrypt.app/Contents/Resources/doc/HTML/en/Donation_Bank.html \
    /Applications/VeraCrypt.app/Contents/Resources/doc/HTML/en/bank_30x30.png \
    /Applications/VeraCrypt.app/Contents/Resources/doc/HTML/ru/Donation_Bank.html \
    /Applications/VeraCrypt.app/Contents/Resources/doc/HTML/ru/bank_30x30.png \
    /Applications/VeraCrypt.app/Contents/Resources/doc/HTML/zh-cn/Donation_Bank.html \
    /Applications/VeraCrypt.app/Contents/Resources/doc/HTML/zh-cn/bank_30x30.png

# create simlink to VeraCrypt binary in /usr/local/bin
if !([ -e "/usr/local/bin/veracrypt" ])
then
    ln -s /Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt /usr/local/bin/veracrypt
fi

exit 0
