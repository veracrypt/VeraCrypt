This archive contains the source code of VeraCrypt.
It is based on original TrueCrypt 7.1a with security enhancements and modifications.


Important
=========

You may use the source code contained in this archive only if you accept and
agree to the license terms contained in the file 'License.txt', which is
included in this archive.

Note that the license specifies, for example, that a derived work must not be
called 'TrueCrypt' or 'VeraCrypt'



Contents
========

I. Windows
   Requirements for Building VeraCrypt for Windows
   Instructions for Building VeraCrypt for Windows
	Instructions for Signing and Packaging VeraCrypt for Windows

II. Linux and Mac OS X
    Requirements for Building VeraCrypt for Linux and Mac OS X
    Instructions for Building VeraCrypt for Linux and Mac OS X
	Mac OS X specifics

III. FreeBSD and OpenSolaris

IV. Third-Party Developers (Contributors)

V. Legal Information

VI. Further Information



I. Windows
==========

Requirements for Building VeraCrypt for Windows:
------------------------------------------------

- Microsoft Visual C++ 2010 SP1 (Professional Edition or compatible)
- Microsoft Visual C++ 1.52 (available from MSDN Subscriber Downloads)
- Microsoft Windows SDK for Windows 7.1 (configured for Visual C++ 2010)
- Microsoft Windows SDK for Windows 8.1 (needed for SHA-256 code signing)
- Microsoft Windows Driver Kit 7.1.0 (build 7600.16385.1)
- NASM assembler 2.08 or compatible
- gzip compressor
- upx packer (available at http://upx.sourceforge.net/)

IMPORTANT:

The 64-bit editions of Windows Vista and later versions of Windows, and in
some cases (e.g. playback of HD DVD content) also the 32-bit editions, do not
allow the VeraCrypt driver to run without an appropriate digital signature.
Therefore, all .sys files in official VeraCrypt binary packages are digitally
signed with the digital certificate of the IDRIX, which was
issued by Thawte certification authority. At the end of each official .exe and
.sys file, there are embedded digital signatures and all related certificates
(i.e. all certificates in the relevant certification chain, such as the
certification authority certificates, CA-MS cross-certificate, and the
IDRIX certificate).
Keep this in mind if you compile VeraCrypt
and compare your binaries with the official binaries. If your binaries are
unsigned, the sizes of the official binaries will usually be approximately
10 KB greater than sizes of your binaries (there may be further differences
if you use a different version of the compiler, or if you install a different
or no service pack for Visual Studio, or different hotfixes for it, or if you
use different versions of the required SDKs).


Instructions for Building VeraCrypt for Windows:
------------------------------------------------

1) Create an environment variable 'MSVC16_ROOT' pointing to the folder 'MSVC15'
   extracted from the Visual C++ 1.52 self-extracting package.

   Note: The 16-bit installer MSVC15\SETUP.EXE cannot be run on 64-bit Windows,
   but it is actually not necessary to run it. You only need to extract the
   folder 'MSVC15', which contains the 32-bit binaries required to build the
   VeraCrypt Boot Loader.

2) If you have installed the Windows Driver Development Kit in another
   directory than '%SYSTEMDRIVE%\WinDDK', create an environment variable
   'WINDDK_ROOT' pointing to the DDK installation directory.

3) Open the solution file 'VeraCrypt.sln' in Microsoft Visual Studio 2010.

4) Select 'All' as the active solution configuration.

5) Build the solution.

6) If successful, there should be newly built VeraCrypt binaries in the
   'Release' folder.

Instructions for Signing and Packaging VeraCrypt for Windows:
-------------------------------------------------------------

First, create an environment variable 'WSDK81' pointing to the Windows SDK
for Windows 8.1 installation directory.
The folder "Signing" contains a batch file (sign.bat) that will sign all
VeraCrypt components using a code signing certificate present on the
certificate store and also build the final installation setup.
The batch file suppose that the code signing certificate is issued by Thawt.
This is the case for IDRIX's certificate. If yours is issued by another CA,
then you should put the Root and Intermediate certificates in the "Signing"
folder and then modify sign.bat accordingly.

VeraCrypt EFI Boot Loader:
--------------------------

VeraCrypt source code contains pre-built EFI binaries under src\Boot\EFI.
The source code of VeraCrypt EFI Boot Loader is licensed under LGPL and 
it is available at https://github.com/veracrypt/VeraCrypt-DCS.
For build instructions, please refer to the file src\Boot\EFI\Readme.txt.


II. Linux and Mac OS X
======================

Requirements for Building VeraCrypt for Linux and Mac OS X:
-----------------------------------------------------------

- GNU Make
- GNU C++ Compiler 4.0 or compatible
- Apple Xcode (Mac OS X only)
- NASM assembler 2.08 or compatible (x86/x64 architecture only)
- pkg-config
- makeself (Linux only)
- wxWidgets 3.0 shared library and header files installed or
  wxWidgets 3.0 library source code (available at http://www.wxwidgets.org)
- FUSE library and header files (available at https://github.com/libfuse/libfuse
  and https://osxfuse.github.io/)


Instructions for Building VeraCrypt for Linux and Mac OS X:
-----------------------------------------------------------

1) Change the current directory to the root of the VeraCrypt source code.

2) If you have no wxWidgets shared library installed, run the following
   command to configure the wxWidgets static library for VeraCrypt and to
   build it:

   $ make WXSTATIC=1 WX_ROOT=/usr/src/wxWidgets wxbuild

   The variable WX_ROOT must point to the location of the source code of the
   wxWidgets library. Output files will be placed in the './wxrelease/'
   directory.

3) To build VeraCrypt, run the following command:

   $ make

   or if you have no wxWidgets shared library installed:

   $ make WXSTATIC=1

4) If successful, the VeraCrypt executable should be located in the directory
   'Main'.

By default, a universal executable supporting both graphical and text user
interface (through the switch --text) is built.
On Linux, a console-only executable, which requires no GUI library, can be
built using the 'NOGUI' parameter:

   $ make NOGUI=1 WXSTATIC=1 WX_ROOT=/usr/src/wxWidgets wxbuild
   $ make NOGUI=1 WXSTATIC=1

On MacOSX, building a console-only executable is not supported.

Mac OS X specifics:
-----------------------------------------------------------

Under MacOSX, the SDK for OSX 10.7 is used by default. To use another version
of the SDK (i.e. 10.6), you can export the environment variable VC_OSX_TARGET:

	$ export VC_OSX_TARGET=10.6


Before building under MacOSX, pkg-config must be installed if not yet available.
Get it from http://pkgconfig.freedesktop.org/releases/pkg-config-0.28.tar.gz and
compile using the following commands :

	$ ./configure --with-internal-glib
	$ make
	$ sudo make install

After making sure pkg-config is available, download and install OSXFuse from
https://osxfuse.github.io/ (MacFUSE compatibility layer must selected)

The script build_veracrypt_macosx.sh available under "src/Build" performs the
full build of VeraCrypt including the creation of the installer pkg. It expects
to find the wxWidgets 3.0.2 sources at the same level as where you put
VeraCrypt sources (i.e. if "src" path is "/Users/joe/Projects/VeraCrypt/src"
then wxWidgets should be at "/Users/joe/Projects/wxWidgets-3.0.2")

The build process uses Code Signing certificates whose ID is specified in
src/Main/Main.make (lines 167 & 169). You'll have to modify these lines to put
the ID of your Code Signing certificates or comment them if you don't have one.

Because of incompatibility issues with OSXFUSE, the SDK 10.9 generates a
VeraCrypt binary that has issues communicating with the OSXFUSE kernel extension.
Thus, we recommend to use the SDK 10.8 or earlier for building VeraCrypt.



III. FreeBSD and OpenSolaris
============================

FreeBSD and OpenSolaris are not yet supported.



IV. Third-Party Developers (Contributors)
=========================================

If you intend to implement a feature, please contact us first to make sure:

1) That the feature has not been implemented (we may have already implemented
   it, but haven't released the code yet).
2) That the feature is acceptable.
3) Whether we need help of third-party developers with implementing the feature.

Information on how to contact us can be found at:
https://veracrypt.codeplex.com/



V. Legal Information
====================

Copyright Information
---------------------

This software as a whole:
Copyright (c) 2013-2016 IDRIX. All rights reserved.

Portions of this software:
Copyright (c) 2013-2016 IDRIX. All rights reserved.
Copyright (c) 2003-2012 TrueCrypt Developers Association. All rights reserved.
Copyright (c) 1998-2000 Paul Le Roux. All rights reserved.
Copyright (c) 1998-2008 Brian Gladman, Worcester, UK. All rights reserved.
Copyright (c) 1995-2013 Jean-loup Gailly and Mark Adler.
Copyright (c) 2016 Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) Dieter Baron and Thomas Klausner.
Copyright (c) 2013, Alexey Degtyarev. All rights reserved.

For more information, please see the legal notices attached to parts of the
source code.

Trademark Information
---------------------

Any trademarks contained in the source code, binaries, and/or in the
documentation, are the sole property of their respective owners.



VI. Further Information
=======================

http://www.veracrypt.fr
