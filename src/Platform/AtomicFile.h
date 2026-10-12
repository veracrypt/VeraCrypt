/*
 Copyright (c) 2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Platform_AtomicFile
#define TC_HEADER_Platform_AtomicFile

#include "File.h"

namespace VeraCrypt
{
	// Keep the destination intact until all output is ready. Temporary files and
	// the published result have mode 0600, including when replacing an old file.
	class AtomicFile
	{
	public:
		explicit AtomicFile (const FilePath &destination);
		~AtomicFile ();
		File &GetFile () { return Output; }
		// Flush the contents, replace the destination, and sync its directory.
		// Symlinks and other non-regular destinations are refused. Unsupported
		// directory fsync is tolerated; other failures after publication throw
		// AtomicFilePublished, indicating that the complete file now exists.
		void Commit ();

	private:
		FilePath Destination;
		string TemporaryPath;
		File Output;
		File ParentDirectory;

		AtomicFile (const AtomicFile &);
		AtomicFile &operator= (const AtomicFile &);
	};
}

#endif // TC_HEADER_Platform_AtomicFile
