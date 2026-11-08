#include "Tcdefs.h"
#include <windows.h>
#include "SelfExtract.h"

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	wchar_t SetupFilesDir[TC_MAX_PATH];
	wchar_t *s;
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);

	if (lpCmdLine[0] == L'/' && lpCmdLine[1] == L'p')
	{
		SelfExtractStartupInit();
		GetModuleFileName (NULL, SetupFilesDir, ARRAYSIZE (SetupFilesDir));
		s = wcsrchr (SetupFilesDir, L'\\');
		if (s)
			s[1] = 0;

		/*
		 * Create a self-extracting package containing the traveler files.
		 * The MSI traveler creation path verifies this IDRIX-signed package
		 * instead of verifying individual WHQL-signed driver files.
		 */
		MakeSelfExtractingPackage (NULL, SetupFilesDir, FALSE);
	}

	return 0;
}
