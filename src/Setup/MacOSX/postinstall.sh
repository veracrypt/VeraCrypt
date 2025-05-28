#!/bin/bash

if !([ -e "/usr/local/lib/libfuse.2.dylib" ])
then
	ln -s /usr/local/lib/libosxfuse.2.dylib /usr/local/lib/libfuse.2.dylib
fi

chmod -R go-w /Applications/VeraCrypt.app

# create simlink to VeraCrypt binary in /usr/local/bin
if !([ -e "/usr/local/bin/veracrypt" ])
then
    ln -s /Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt /usr/local/bin/veracrypt
fi

exit 0
