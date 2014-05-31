/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Platform/Platform.h"
#include "Resources.h"

#ifdef TC_WINDOWS
#include "Main/resource.h"
#endif

namespace TrueCrypt
{

#ifdef TC_WINDOWS
	static ConstBufferPtr GetWindowsResource (const wchar_t *resourceType, const wchar_t *resourceName)
	{
		HGLOBAL hResL; 
		HRSRC hRes;

		hRes = FindResource (NULL, resourceName, resourceType);
		throw_sys_if (!hRes);
		hResL = LoadResource (NULL, hRes);
		throw_sys_if (!hResL);

		const byte *resPtr = (const byte *) LockResource (hResL);
		throw_sys_if (!resPtr);

		return ConstBufferPtr (resPtr, SizeofResource (NULL, hRes));
	}
#endif // TC_WINDOWS


	string Resources::GetLanguageXml ()
	{
#ifdef TC_WINDOWS
		ConstBufferPtr res = GetWindowsResource (L"XML", L"IDR_LANGUAGE");
		Buffer strBuf (res.Size() + 1);
		strBuf.Zero();
		strBuf.CopyFrom (res);
		return string (reinterpret_cast <char *> (strBuf.Ptr()));
#else
		static const char LanguageXml[] =
		{
#			include "Common/Language.xml.h"
			, 0
		};

		return string (LanguageXml);
#endif
	}

	string Resources::GetLegalNotices ()
	{
#ifdef TC_WINDOWS
		ConstBufferPtr res = GetWindowsResource (L"TEXT", L"IDR_LICENSE");
		Buffer strBuf (res.Size() + 1);
		strBuf.Zero();
		strBuf.CopyFrom (res);
		return string (reinterpret_cast <char *> (strBuf.Ptr()));
#else
		static const char License[] =
		{
#			include "License.txt.h"
			, 0
		};

		return string (License);
#endif
	}


#ifndef TC_NO_GUI

	wxBitmap Resources::GetDriveIconBitmap ()
	{
#ifdef TC_WINDOWS
		return wxBitmap (L"IDB_DRIVE_ICON", wxBITMAP_TYPE_BMP_RESOURCE).ConvertToImage().Resize (wxSize (16, 12), wxPoint (0, 0));
#else
		static const byte DriveIcon[] =
		{
#			include "Mount/Drive_icon_96dpi.bmp.h"
		};

		wxMemoryInputStream stream (DriveIcon, sizeof (DriveIcon));
		return wxBitmap (wxImage (stream).Resize (wxSize (16, 12), wxPoint (0, 0)));
#endif
	}

	wxBitmap Resources::GetDriveIconMaskBitmap ()
	{
#ifdef TC_WINDOWS
		wxImage image = wxBitmap (L"IDB_DRIVE_ICON_MASK", wxBITMAP_TYPE_BMP_RESOURCE).ConvertToImage().Resize (wxSize (16, 12), wxPoint (0, 0));
		return wxBitmap (image.ConvertToMono (0, 0, 0), 1);
#else
		static const byte DriveIconMask[] =
		{
#			include "Mount/Drive_icon_mask_96dpi.bmp.h"
		};

		wxMemoryInputStream stream (DriveIconMask, sizeof (DriveIconMask));
		wxImage image (stream);
		image.Resize (wxSize (16, 12), wxPoint (0, 0));

#	ifdef __WXGTK__
		return wxBitmap (image.ConvertToMono (0, 0, 0), 1);
#	else
		return wxBitmap (image);
#	endif
#endif
	}


	wxBitmap Resources::GetLogoBitmap ()
	{
#ifdef TC_WINDOWS
		return wxBitmap (L"IDB_LOGO", wxBITMAP_TYPE_BMP_RESOURCE);
#else
		static const byte Logo[] =
		{
#			include "Mount/Logo_96dpi.bmp.h"
		};

		wxMemoryInputStream stream (Logo, sizeof (Logo));
		return wxBitmap (wxImage (stream));
#endif
	}

	wxBitmap Resources::GetTextualLogoBitmap ()
	{
#ifdef TC_WINDOWS
		return wxBitmap (L"IDB_TEXTUAL_LOGO", wxBITMAP_TYPE_BMP_RESOURCE);
#else
		static const byte Logo[] =
		{
#			include "Common/Textual_logo_96dpi.bmp.h"
		};

		wxMemoryInputStream stream (Logo, sizeof (Logo));
		return wxBitmap (wxImage (stream));
#endif
	}

	wxIcon Resources::GetTrueCryptIcon ()
	{
#ifdef TC_WINDOWS
		return wxIcon (L"IDI_TRUECRYPT_ICON", wxBITMAP_TYPE_ICO_RESOURCE, 16, 16);
#else
#		include "Resources/Icons/TrueCrypt-16x16.xpm"
		return wxIcon (TrueCryptIcon16x16);
#endif
	}

	wxBitmap Resources::GetVolumeCreationWizardBitmap (int height)
	{
#ifdef TC_WINDOWS
		return wxBitmap (L"IDB_VOLUME_WIZARD_BITMAP", wxBITMAP_TYPE_BMP_RESOURCE);
#else
		static const byte VolumeWizardIcon[] =
		{
#			include "Format/TrueCrypt_Wizard.bmp.h"
		};

		wxMemoryInputStream stream (VolumeWizardIcon, sizeof (VolumeWizardIcon));

		wxImage image (stream);
		if (height != -1)
		{
			double scaleFactor = double (height) / double (image.GetHeight());
			image.Rescale (int (image.GetWidth() * scaleFactor), int (image.GetHeight() * scaleFactor), wxIMAGE_QUALITY_HIGH);
		}

		return wxBitmap (image);
#endif
	}

#endif // !TC_NO_GUI

}
