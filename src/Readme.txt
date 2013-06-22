This archive contains the source code of TrueCrypt 7.1a.


Important
=========

You may use the source code contained in this archive only if you accept and
agree to the license terms contained in the file 'License.txt', which is
included in this archive.

Note that the license specifies, for example, that a derived work must not be
called 'TrueCrypt'.



Contents
========

I. Windows
	Requirements for Building TrueCrypt for Windows
	Instructions for Building TrueCrypt for Windows

II. Linux and Mac OS X
	Requirements for Building TrueCrypt for Linux and Mac OS X
	Instructions for Building TrueCrypt for Linux and Mac OS X
	
III. FreeBSD and OpenSolaris

IV. Third-Party Developers (Contributors)

V. Legal Information

VI. Further Information



I. Windows
==========

Requirements for Building TrueCrypt for Windows:
------------------------------------------------

- Microsoft Visual C++ 2008 SP1 (Professional Edition or compatible)
- Microsoft Visual C++ 1.52 (available from MSDN Subscriber Downloads)
- Microsoft Windows SDK for Windows 7 (configured for Visual C++)
- Microsoft Windows Driver Kit 7.1.0 (build 7600.16385.1)
- RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki) 2.20
  header files (available at ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20)
- NASM assembler 2.08 or compatible
- gzip compressor

IMPORTANT:

The 64-bit editions of Windows Vista and later versions of Windows, and in
some cases (e.g. playback of HD DVD content) also the 32-bit editions, do not
allow the TrueCrypt driver to run without an appropriate digital signature.
Therefore, all .sys files in official TrueCrypt binary packages are digitally
signed with the digital certificate of the TrueCrypt Foundation, which was
issued by a certification authority. At the end of each official .exe and
.sys file, there are embedded digital signatures and all related certificates
(i.e. all certificates in the relevant certification chain, such as the
certification authority certificates, CA-MS cross-certificate, and the
TrueCrypt Foundation certificate). Keep this in mind if you compile TrueCrypt
and compare your binaries with the official binaries. If your binaries are
unsigned, the sizes of the official binaries will usually be approximately
10 KB greater than sizes of your binaries (there may be further differences
if you use a different version of the compiler, or if you install a different
or no service pack for Visual Studio, or different hotfixes for it, or if you
use different versions of the required SDKs).


Instructions for Building TrueCrypt for Windows:
------------------------------------------------

1) Create an environment variable 'MSVC16_ROOT' pointing to the folder 'MSVC15'
   extracted from the Visual C++ 1.52 self-extracting package.

   Note: The 16-bit installer MSVC15\SETUP.EXE cannot be run on 64-bit Windows,
   but it is actually not necessary to run it. You only need to extract the
   folder 'MSVC15', which contains the 32-bit binaries required to build the
   TrueCrypt Boot Loader.

2) If you have installed the Windows Driver Development Kit in another
   directory than '%SYSTEMDRIVE%\WinDDK', create an environment variable
   'WINDDK_ROOT' pointing to the DDK installation directory.

3) Copy the PKCS #11 header files to a standard include path or create an
   environment variable 'PKCS11_INC' pointing to the directory where
   the PKCS #11 header files are installed.

4) Open the solution file 'TrueCrypt.sln' in Microsoft Visual Studio 2008.

5) Select 'All' as the active solution configuration.

6) Build the solution.

7) If successful, there should be newly built TrueCrypt binaries in the
   'Release' folder.



II. Linux and Mac OS X
======================

Requirements for Building TrueCrypt for Linux and Mac OS X:
-----------------------------------------------------------

- GNU Make
- GNU C++ Compiler 4.0 or compatible
- Apple Xcode (Mac OS X only)
- NASM assembler 2.08 or compatible (x86/x64 architecture only)
- pkg-config
- wxWidgets 2.8 shared library and header files installed or
  wxWidgets 2.8 library source code (available at http://www.wxwidgets.org)
- FUSE library and header files (available at http://fuse.sourceforge.net
  and http://code.google.com/p/macfuse)
- RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki) 2.20
  header files (available at ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20)
  located in a standard include path or in a directory defined by the
  environment variable 'PKCS11_INC'.


Instructions for Building TrueCrypt for Linux and Mac OS X:
-----------------------------------------------------------

1) Change the current directory to the root of the TrueCrypt source code.

2) If you have no wxWidgets shared library installed, run the following
   command to configure the wxWidgets static library for TrueCrypt and to
   build it: 

   $ make WX_ROOT=/usr/src/wxWidgets wxbuild

   The variable WX_ROOT must point to the location of the source code of the
   wxWidgets library. Output files will be placed in the './wxrelease/'
   directory.

3) To build TrueCrypt, run the following command:

   $ make

   or if you have no wxWidgets shared library installed:
   
   $ make WXSTATIC=1

4) If successful, the TrueCrypt executable should be located in the directory
   'Main'.

By default, a universal executable supporting both graphical and text user
interface is built. To build a console-only executable, which requires no GUI
library, use the 'NOGUI' parameter:

   $ make NOGUI=1 WX_ROOT=/usr/src/wxWidgets wxbuild
   $ make NOGUI=1 WXSTATIC=1



III. FreeBSD and OpenSolaris
============================

Support status for FreeBSD: http://www.truecrypt.org/misc/freebsd
Support status for OpenSolaris: http://www.truecrypt.org/misc/opensolaris



IV. Third-Party Developers (Contributors)
=========================================

If you intend to implement a feature, please contact us first to make sure:

1) That the feature has not been implemented (we may have already implemented
   it, but haven't released the code yet).
2) That the feature is acceptable.
3) Whether we need help of third-party developers with implementing the feature.

Information on how to contact us can be found at:
http://www.truecrypt.org/contact



V. Legal Information
====================

Copyright Information
---------------------

This software as a whole:
Copyright (c) 2012 TrueCrypt Developers Association. All rights reserved.

Portions of this software:
Copyright (c) 2003-2012 TrueCrypt Developers Association. All rights reserved.
Copyright (c) 1998-2000 Paul Le Roux. All rights reserved.
Copyright (c) 1998-2008 Brian Gladman, Worcester, UK. All rights reserved.
Copyright (c) 2002-2004 Mark Adler. All rights reserved.
For more information, please see the legal notices attached to parts of the
source code.

Trademark Information
---------------------

Any trademarks contained in the source code, binaries, and/or in the 
documentation, are the sole property of their respective owners.



VI. Further Information
=======================

http://www.truecrypt.org
