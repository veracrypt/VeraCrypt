// XZip.h  Version 1.3
//
// Authors:      Mark Adler et al. (see below)
//
// Modified by:  Lucian Wischik
//               lu@wischik.com
//
// Version 1.0   - Turned C files into just a single CPP file
//               - Made them compile cleanly as C++ files
//               - Gave them simpler APIs
//               - Added the ability to zip/unzip directly in memory without 
//                 any intermediate files
// 
// Modified by:  Hans Dietrich
//               hdietrich@gmail.com
//
///////////////////////////////////////////////////////////////////////////////
//
// Lucian Wischik's comments:
// --------------------------
// THIS FILE is almost entirely based upon code by info-zip.
// It has been modified by Lucian Wischik.
// The original code may be found at http://www.info-zip.org
// The original copyright text follows.
//
///////////////////////////////////////////////////////////////////////////////
//
// Original authors' comments:
// ---------------------------
// This is version 2002-Feb-16 of the Info-ZIP copyright and license. The 
// definitive version of this document should be available at 
// ftp://ftp.info-zip.org/pub/infozip/license.html indefinitely.
// 
// Copyright (c) 1990-2002 Info-ZIP.  All rights reserved.
//
// For the purposes of this copyright and license, "Info-ZIP" is defined as
// the following set of individuals:
//
//   Mark Adler, John Bush, Karl Davis, Harald Denker, Jean-Michel Dubois,
//   Jean-loup Gailly, Hunter Goatley, Ian Gorman, Chris Herborth, Dirk Haase,
//   Greg Hartwig, Robert Heath, Jonathan Hudson, Paul Kienitz, 
//   David Kirschbaum, Johnny Lee, Onno van der Linden, Igor Mandrichenko, 
//   Steve P. Miller, Sergio Monesi, Keith Owens, George Petrov, Greg Roelofs, 
//   Kai Uwe Rommel, Steve Salisbury, Dave Smith, Christian Spieler, 
//   Antoine Verheijen, Paul von Behren, Rich Wales, Mike White
//
// This software is provided "as is", without warranty of any kind, express
// or implied.  In no event shall Info-ZIP or its contributors be held liable
// for any direct, indirect, incidental, special or consequential damages
// arising out of the use of or inability to use this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
//    1. Redistributions of source code must retain the above copyright notice,
//       definition, disclaimer, and this list of conditions.
//
//    2. Redistributions in binary form (compiled executables) must reproduce 
//       the above copyright notice, definition, disclaimer, and this list of 
//       conditions in documentation and/or other materials provided with the 
//       distribution. The sole exception to this condition is redistribution 
//       of a standard UnZipSFX binary as part of a self-extracting archive; 
//       that is permitted without inclusion of this license, as long as the 
//       normal UnZipSFX banner has not been removed from the binary or disabled.
//
//    3. Altered versions--including, but not limited to, ports to new 
//       operating systems, existing ports with new graphical interfaces, and 
//       dynamic, shared, or static library versions--must be plainly marked 
//       as such and must not be misrepresented as being the original source.  
//       Such altered versions also must not be misrepresented as being 
//       Info-ZIP releases--including, but not limited to, labeling of the 
//       altered versions with the names "Info-ZIP" (or any variation thereof, 
//       including, but not limited to, different capitalizations), 
//       "Pocket UnZip", "WiZ" or "MacZip" without the explicit permission of 
//       Info-ZIP.  Such altered versions are further prohibited from 
//       misrepresentative use of the Zip-Bugs or Info-ZIP e-mail addresses or 
//       of the Info-ZIP URL(s).
//
//    4. Info-ZIP retains the right to use the names "Info-ZIP", "Zip", "UnZip",
//       "UnZipSFX", "WiZ", "Pocket UnZip", "Pocket Zip", and "MacZip" for its 
//       own source and binary releases.
//
///////////////////////////////////////////////////////////////////////////////

#ifndef XZIP_H
#define XZIP_H

// ZIP functions -- for creating zip files
// This file is a repackaged form of the Info-Zip source code available
// at www.info-zip.org. The original copyright notice may be found in
// zip.cpp. The repackaging was done by Lucian Wischik to simplify its
// use in Windows/C++.

#ifndef XUNZIP_H
DECLARE_HANDLE(HZIP);		// An HZIP identifies a zip file that is being created
#endif

typedef DWORD ZRESULT;		// result codes from any of the zip functions. Listed later.

// flag values passed to some functions
#define ZIP_HANDLE   1
#define ZIP_FILENAME 2
#define ZIP_MEMORY   3
#define ZIP_FOLDER   4


///////////////////////////////////////////////////////////////////////////////
//
// CreateZip()
//
// Purpose:     Create a zip archive file
//
// Parameters:  z      - archive file name if flags is ZIP_FILENAME;  for other
//                       uses see below
//              len    - for memory (ZIP_MEMORY) should be the buffer size;
//                       for other uses, should be 0
//              flags  - indicates usage, see below;  for files, this will be
//                       ZIP_FILENAME
//
// Returns:     HZIP   - non-zero if zip archive created ok, otherwise 0
//
HZIP CreateZip(void *z, unsigned int len, DWORD flags);
// CreateZip - call this to start the creation of a zip file.
// As the zip is being created, it will be stored somewhere:
// to a pipe:              CreateZip(hpipe_write, 0,ZIP_HANDLE);
// in a file (by handle):  CreateZip(hfile, 0,ZIP_HANDLE);
// in a file (by name):    CreateZip("c:\\test.zip", 0,ZIP_FILENAME);
// in memory:              CreateZip(buf, len,ZIP_MEMORY);
// or in pagefile memory:  CreateZip(0, len,ZIP_MEMORY);
// The final case stores it in memory backed by the system paging file,
// where the zip may not exceed len bytes. This is a bit friendlier than
// allocating memory with new[]: it won't lead to fragmentation, and the
// memory won't be touched unless needed.
// Note: because pipes don't allow random access, the structure of a zipfile
// created into a pipe is slightly different from that created into a file
// or memory. In particular, the compressed-size of the item cannot be
// stored in the zipfile until after the item itself. (Also, for an item added
// itself via a pipe, the uncompressed-size might not either be known until
// after.) This is not normally a problem. But if you try to unzip via a pipe
// as well, then the unzipper will not know these things about the item until
// after it has been unzipped. Therefore: for unzippers which don't just write
// each item to disk or to a pipe, but instead pre-allocate memory space into
// which to unzip them, then either you have to create the zip not to a pipe,
// or you have to add items not from a pipe, or at least when adding items
// from a pipe you have to specify the length.


///////////////////////////////////////////////////////////////////////////////
//
// ZipAdd()
//
// Purpose:     Add a file to a zip archive
//
// Parameters:  hz      - handle to an open zip archive
//              dstzn   - name used inside the zip archive to identify the file
//              src     - for a file (ZIP_FILENAME) this specifies the filename
//                        to be added to the archive;  for other uses, see below
//              len     - for memory (ZIP_MEMORY) this specifies the buffer 
//                        length;  for other uses, this should be 0
//              flags   - indicates usage, see below;  for files, this will be
//                        ZIP_FILENAME
//
// Returns:     ZRESULT - ZR_OK if success, otherwise some other value
//
ZRESULT ZipAdd(HZIP hz, const TCHAR *dstzn, void *src, unsigned int len, DWORD flags);
// ZipAdd - call this for each file to be added to the zip.
// dstzn is the name that the file will be stored as in the zip file.
// The file to be added to the zip can come
// from a pipe:  ZipAdd(hz,"file.dat", hpipe_read,0,ZIP_HANDLE);
// from a file:  ZipAdd(hz,"file.dat", hfile,0,ZIP_HANDLE);
// from a fname: ZipAdd(hz,"file.dat", "c:\\docs\\origfile.dat",0,ZIP_FILENAME);
// from memory:  ZipAdd(hz,"subdir\\file.dat", buf,len,ZIP_MEMORY);
// (folder):     ZipAdd(hz,"subdir",   0,0,ZIP_FOLDER);
// Note: if adding an item from a pipe, and if also creating the zip file itself
// to a pipe, then you might wish to pass a non-zero length to the ZipAdd
// function. This will let the zipfile store the items size ahead of the
// compressed item itself, which in turn makes it easier when unzipping the
// zipfile into a pipe.


///////////////////////////////////////////////////////////////////////////////
//
// CloseZip()
//
// Purpose:     Close an open zip archive
//
// Parameters:  hz      - handle to an open zip archive
//
// Returns:     ZRESULT - ZR_OK if success, otherwise some other value
//
ZRESULT CloseZip(HZIP hz);
// CloseZip - the zip handle must be closed with this function.


ZRESULT ZipGetMemory(HZIP hz, void **buf, unsigned long *len);
// ZipGetMemory - If the zip was created in memory, via ZipCreate(0,ZIP_MEMORY),
// then this function will return information about that memory block.
// buf will receive a pointer to its start, and len its length.
// Note: you can't add any more after calling this.


unsigned int FormatZipMessage(ZRESULT code, char *buf,unsigned int len);
// FormatZipMessage - given an error code, formats it as a string.
// It returns the length of the error message. If buf/len points
// to a real buffer, then it also writes as much as possible into there.



// These are the result codes:
#define ZR_OK         0x00000000     // nb. the pseudo-code zr-recent is never returned,
#define ZR_RECENT     0x00000001     // but can be passed to FormatZipMessage.
// The following come from general system stuff (e.g. files not openable)
#define ZR_GENMASK    0x0000FF00
#define ZR_NODUPH     0x00000100     // couldn't duplicate the handle
#define ZR_NOFILE     0x00000200     // couldn't create/open the file
#define ZR_NOALLOC    0x00000300     // failed to allocate some resource
#define ZR_WRITE      0x00000400     // a general error writing to the file
#define ZR_NOTFOUND   0x00000500     // couldn't find that file in the zip
#define ZR_MORE       0x00000600     // there's still more data to be unzipped
#define ZR_CORRUPT    0x00000700     // the zipfile is corrupt or not a zipfile
#define ZR_READ       0x00000800     // a general error reading the file
// The following come from mistakes on the part of the caller
#define ZR_CALLERMASK 0x00FF0000
#define ZR_ARGS       0x00010000     // general mistake with the arguments
#define ZR_NOTMMAP    0x00020000     // tried to ZipGetMemory, but that only works on mmap zipfiles, which yours wasn't
#define ZR_MEMSIZE    0x00030000     // the memory size is too small
#define ZR_FAILED     0x00040000     // the thing was already failed when you called this function
#define ZR_ENDED      0x00050000     // the zip creation has already been closed
#define ZR_MISSIZE    0x00060000     // the indicated input file size turned out mistaken
#define ZR_PARTIALUNZ 0x00070000     // the file had already been partially unzipped
#define ZR_ZMODE      0x00080000     // tried to mix creating/opening a zip 
// The following come from bugs within the zip library itself
#define ZR_BUGMASK    0xFF000000
#define ZR_NOTINITED  0x01000000     // initialisation didn't work
#define ZR_SEEK       0x02000000     // trying to seek in an unseekable file
#define ZR_NOCHANGE   0x04000000     // changed its mind on storage, but not allowed
#define ZR_FLATE      0x05000000     // an internal error in the de/inflation code



// e.g.
//
// (1) Traditional use, creating a zipfile from existing files
//     HZIP hz = CreateZip("c:\\temp.zip",0,ZIP_FILENAME);
//     ZipAdd(hz,"src1.txt",  "c:\\src1.txt",0,ZIP_FILENAME);
//     ZipAdd(hz,"src2.bmp",  "c:\\src2_origfn.bmp",0,ZIP_FILENAME);
//     CloseZip(hz);
//
// (2) Memory use, creating an auto-allocated mem-based zip file from various sources
//     HZIP hz = CreateZip(0,100000,ZIP_MEMORY);
//     // adding a conventional file...
//     ZipAdd(hz,"src1.txt",  "c:\\src1.txt",0,ZIP_FILENAME);
//     // adding something from memory...
//     char buf[1000]; for (int i=0; i<1000; i++) buf[i]=(char)(i&0x7F);
//     ZipAdd(hz,"file.dat",  buf,1000,ZIP_MEMORY);
//     // adding something from a pipe...
//     HANDLE hread,hwrite; CreatePipe(&hread,&write,NULL,0);
//     HANDLE hthread = CreateThread(ThreadFunc,(void*)hwrite);
//     ZipAdd(hz,"unz3.dat",  hread,0,ZIP_HANDLE);
//     WaitForSingleObject(hthread,INFINITE);
//     CloseHandle(hthread); CloseHandle(hread);
//     ... meanwhile DWORD CALLBACK ThreadFunc(void *dat)
//                   { HANDLE hwrite = (HANDLE)dat;
//                     char buf[1000]={17};
//                     DWORD writ; WriteFile(hwrite,buf,1000,&writ,NULL);
//                     CloseHandle(hwrite);
//                     return 0;
//                   }
//     // and now that the zip is created, let's do something with it:
//     void *zbuf; unsigned long zlen; ZipGetMemory(hz,&zbuf,&zlen);
//     HANDLE hfz = CreateFile("test2.zip",GENERIC_WRITE,CREATE_ALWAYS);
//     DWORD writ; WriteFile(hfz,zbuf,zlen,&writ,NULL);
//     CloseHandle(hfz);
//     CloseZip(hz);
//
// (3) Handle use, for file handles and pipes
//     HANDLE hzread,hzwrite; CreatePipe(&hzread,&hzwrite);
//     HANDLE hthread = CreateThread(ZipReceiverThread,(void*)hread);
//     HZIP hz = ZipCreate(hzwrite,ZIP_HANDLE);
//     // ... add to it
//     CloseZip(hz);
//     CloseHandle(hzwrite);
//     WaitForSingleObject(hthread,INFINITE);
//     CloseHandle(hthread);
//     ... meanwhile DWORD CALLBACK ThreadFunc(void *dat)
//                   { HANDLE hread = (HANDLE)dat;
//                     char buf[1000];
//                     while (true)
//                     { DWORD red; ReadFile(hread,buf,1000,&red,NULL);
//                       // ... and do something with this zip data we're receiving
//                       if (red==0) break;
//                     }
//                     CloseHandle(hread);
//                     return 0;
//                   }
//


// Now we indulge in a little skullduggery so that the code works whether
// the user has included just zip or both zip and unzip.
// Idea: if header files for both zip and unzip are present, then presumably
// the cpp files for zip and unzip are both present, so we will call
// one or the other of them based on a dynamic choice. If the header file
// for only one is present, then we will bind to that particular one.
HZIP CreateZipZ(void *z,unsigned int len,DWORD flags);
ZRESULT CloseZipZ(HZIP hz);
unsigned int FormatZipMessageZ(ZRESULT code, char *buf,unsigned int len);
bool IsZipHandleZ(HZIP hz);
BOOL AddFolderContent(HZIP hZip, TCHAR* AbsolutePath, TCHAR* DirToAdd);

#define CreateZip CreateZipZ

#ifdef XUNZIP_H
#undef CloseZip
#define CloseZip(hz) (IsZipHandleZ(hz)?CloseZipZ(hz):CloseZipU(hz))
#else
#define CloseZip CloseZipZ
#define FormatZipMessage FormatZipMessageZ
#endif


#endif //XZIP_H
