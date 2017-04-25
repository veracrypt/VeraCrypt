1.2.0 [2017-02-19]
==================

* Support for AES encryption (Winzip version), both encryption
  and decryption.
* Support legacy zip files with >64k entries.
* Fix seeking in zip_source_file if start > 0.
* Add zip_fseek() for seeking in uncompressed data.
* Add zip_ftell() for telling position in uncompressed data.
* Add zip_register_progress_callback() for UI updates during zip_close()

1.1.3 [2016-05-28]
==================

* Fix build on Windows when using autoconf.

1.1.2 [2016-02-19]
==================

* Improve support for 3MF files

1.1.1 [2016-02-07]
==================

* Build fixes for Linux
* Fix some warnings reported by PVS-Studio

1.1 [2016-01-26]
================

* ziptool(1): command line tool to modify zip archives
* Speedups for archives with many entries
* Coverity fixes
* Better APK support
* Support for running tests on Windows
* More build fixes for Windows
* Portability fixes
* Documentation improvements

1.0.1 [2015-05-04]
==================

* Build fixes for Windows.

1.0 [2015-05-03]
================

* Implemented an I/O abstraction layer.
* Added support for native Windows API for files.
* Added support for setting the last modification time for a file.
* Added a new type zip_error_t for errors.
* Added more typedefs for structs.
* Torrentzip support was removed.
* CVE-2015-2331 was fixed.
* Addressed all Coverity CIDs.

0.11.2 [2013-12-19]
===================

* Support querying/setting operating system and external attributes.
* For newly added files, set operating system to UNIX, permissions
  to 0666 (0777 for directories).
* Fix bug when writing zip archives containing files bigger than 4GB.

0.11.1 [2013-04-27]
===================

* Fix bugs in zip_set_file_compression().
* Include Xcode build infrastructure.

0.11 [2013-03-23]
=================

* Added Zip64 support (large file support)
* Added UTF-8 support for file names, file comments, and archive comments
* Changed API for name and comment related functions for UTF-8 support
* Added zip_discard()
* Added ZIP_TRUNCATE for zip_open()
* Added zip_set_file_compression()
* Added API for accessing and modifying extra fields
* Improved API type consistency
* Use gcc4's visibility __attribute__
* More changes for Windows support
* Additional test cases

0.10.1 [2012-03-20]
===================

* Fixed CVE-2012-1162
* Fixed CVE-2012-1163

0.10 [2010-03-18]
=================

* Added zip_get_num_entries(), deprecated zip_get_num_files().
* Better windows support.
* Support for traditional PKWARE encryption added.
* Fix opening archives with more than 65535 entries.
* Fix some memory leaks.
* Fix cmake build and installation
* Fix memory leak in error case in zip_open()
* Fixed CVE-2011-0421 (no security implications though)
* More documentation.

0.9.3 [2010-02-01]
==================

* Include m4/ directory in distribution; some packagers need it.

0.9.2 [2010-01-31]
==================

* Avoid passing uninitialized data to deflate().
* Fix memory leak when closing zip archives.

0.9.1 [2010-01-24]
==================

* Fix infinite loop on reading some broken files.
* Optimization in time conversion (don't call localtime()).
* Clear data descriptor flag in central directory, fixing Open Office files.
* Allow more than 64k entries.

0.9 [2008-07-25]
==================

* on Windows, explictly set dllimport/dllexport
* remove erroneous references to GPL
* add support for torrentzip
* new functions: zip_get_archive_flag, zip_set_archive_flag
* zip_source_zip: add flag to force recompression
* zip_sorce_file: only keep file open while reading from it

0.8 [2007-06-06]
==================

* fix for zip archives larger than 2GiB
* fix zip_error_strerror to include libzip error string
* add support for reading streamed zip files
* new functions: zip_add_dir, zip_error_clear, zip_file_error_clear
* add basic support for building with CMake (incomplete)

0.7.1 [2006-05-18]
==================

* bugfix for zip_close

0.7 [2006-05-06]
================

* struct zip_stat increased for future encryption support
* zip_add return value changed (now returns new index of added file)
* shared library major bump because of previous two
* added functions for reading and writing file and archive comments.
  New functions: zip_get_archive_comment, zip_get_file_comment,
  zip_set_archive_comment, zip_set_file_comment, zip_unchange_archive

0.6.1 [2005-07-14]
==================

* various bug fixes

0.6 [2005-06-09]
================

* first standalone release
* changed license to three-clause BSD
* overhauled API
* added man pages
* install zipcmp and zipmerge
