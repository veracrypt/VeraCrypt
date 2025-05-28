#!/bin/bash

chmod -R go-w /Applications/VeraCrypt.app

# create simlink to VeraCrypt binary in /usr/local/bin
if !([ -e "/usr/local/bin/veracrypt" ])
then
    ln -s /Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt /usr/local/bin/veracrypt
fi

exit 0
