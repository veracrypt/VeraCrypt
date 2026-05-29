/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include "Platform/SystemInfo.h"
#ifdef TC_UNIX
#include <errno.h>
#include <unistd.h>
#include <sys/statvfs.h> // header for statvfs
#include "Platform/Unix/Process.h"
#endif
#include "Core/RandomNumberGenerator.h"
#include "Core/VolumeCreator.h"
#include "Main/Application.h"
#include "Main/GraphicUserInterface.h"
#ifdef TC_MACOSX
#include "Main/MacOSXFormatterDevice.h"
#endif
#include "Main/Resources.h"
#include "VolumeCreationWizard.h"
#include "EncryptionOptionsWizardPage.h"
#include "InfoWizardPage.h"
#include "ProgressWizardPage.h"
#include "SingleChoiceWizardPage.h"
#include "VolumeCreationProgressWizardPage.h"
#include "VolumeFormatOptionsWizardPage.h"
#include "VolumeLocationWizardPage.h"
#include "VolumePasswordWizardPage.h"
#include "VolumePimWizardPage.h"
#include "VolumeSizeWizardPage.h"
#include "WaitDialog.h"

namespace VeraCrypt
{
	class OpenOuterVolumeFunctor : public Functor
	{
		public:
		OpenOuterVolumeFunctor (const DirectoryPath &outerVolumeMountPoint) : OuterVolumeMountPoint (outerVolumeMountPoint) { }

		virtual void operator() ()
		{
			Gui->OpenExplorerWindow (OuterVolumeMountPoint);
		}

		DirectoryPath OuterVolumeMountPoint;
	};

#ifdef TC_MACOSX

	static string DecodeMacOSXPlistXmlString (const string &xmlString)
	{
		string decoded;

		for (size_t i = 0; i < xmlString.size(); ++i)
		{
			if (xmlString[i] != '&')
			{
				decoded += xmlString[i];
				continue;
			}

			if (xmlString.compare (i, 5, "&amp;") == 0)
			{
				decoded += '&';
				i += 4;
			}
			else if (xmlString.compare (i, 4, "&lt;") == 0)
			{
				decoded += '<';
				i += 3;
			}
			else if (xmlString.compare (i, 4, "&gt;") == 0)
			{
				decoded += '>';
				i += 3;
			}
			else if (xmlString.compare (i, 6, "&quot;") == 0)
			{
				decoded += '"';
				i += 5;
			}
			else if (xmlString.compare (i, 6, "&apos;") == 0)
			{
				decoded += '\'';
				i += 5;
			}
			else
				decoded += xmlString[i];
		}

		return decoded;
	}

	static bool ExtractMacOSXPlistString (const string &xml, const string &key, string &value)
	{
		string keyTag = "<key>" + key + "</key>";
		size_t p = xml.find (keyTag);
		if (p == string::npos)
			return false;

		p = xml.find ("<string>", p + keyTag.size());
		if (p == string::npos)
			return false;
		p += 8;

		size_t e = xml.find ("</string>", p);
		if (e == string::npos)
			return false;

		value = DecodeMacOSXPlistXmlString (xml.substr (p, e - p));
		return true;
	}

	static bool ExtractMacOSXPlistBool (const string &xml, const string &key, bool &value)
	{
		string keyTag = "<key>" + key + "</key>";
		size_t p = xml.find (keyTag);
		if (p == string::npos)
			return false;

		p += keyTag.size();
		size_t truePos = xml.find ("<true/>", p);
		size_t falsePos = xml.find ("<false/>", p);
		size_t nextKeyPos = xml.find ("<key>", p);

		if (truePos != string::npos && (nextKeyPos == string::npos || truePos < nextKeyPos)
			&& (falsePos == string::npos || truePos < falsePos))
		{
			value = true;
			return true;
		}

		if (falsePos != string::npos && (nextKeyPos == string::npos || falsePos < nextKeyPos))
		{
			value = false;
			return true;
		}

		return false;
	}

	static list <string> ExtractMacOSXAPFSPhysicalStores (const string &xml)
	{
		list <string> stores;
		size_t arrayPos = xml.find ("<key>APFSPhysicalStores</key>");
		if (arrayPos == string::npos)
			return stores;

		size_t arrayEnd = xml.find ("</array>", arrayPos);
		if (arrayEnd == string::npos)
			return stores;

		for (size_t p = arrayPos; p < arrayEnd; )
		{
			size_t keyPos = xml.find ("<key>APFSPhysicalStore</key>", p);
			size_t alternateKeyPos = xml.find ("<key>DeviceIdentifier</key>", p);

			if (alternateKeyPos != string::npos && alternateKeyPos < arrayEnd
				&& (keyPos == string::npos || alternateKeyPos < keyPos))
				keyPos = alternateKeyPos;

			if (keyPos == string::npos || keyPos >= arrayEnd)
				break;

			size_t stringPos = xml.find ("<string>", keyPos);
			if (stringPos == string::npos || stringPos >= arrayEnd)
				break;
			stringPos += 8;

			size_t stringEnd = xml.find ("</string>", stringPos);
			if (stringEnd == string::npos || stringEnd > arrayEnd)
				break;

			stores.push_back (DecodeMacOSXPlistXmlString (xml.substr (stringPos, stringEnd - stringPos)));
			p = stringEnd + 9;
		}

		return stores;
	}

	static string GetMacOSXDiskutilDevicePath (const VolumePath &devicePath)
	{
		string path = devicePath;

		if (path.find ("/dev/rdisk") == 0)
			path = string ("/dev/disk") + path.substr (10);

		return path;
	}

	static string GetMacOSXDiskutilInfo (const VolumePath &devicePath)
	{
		list <string> args;
		args.push_back ("info");
		args.push_back ("-plist");
		args.push_back (GetMacOSXDiskutilDevicePath (devicePath));

		return Process::Execute ("/usr/sbin/diskutil", args);
	}

	static bool IsMacOSXSystemSupportContent (const string &content)
	{
		string lowerContent = StringConverter::ToLower (content);

		return lowerContent == "efi"
			|| lowerContent == "apple_apfs_isc"
			|| lowerContent == "apple_apfs_recovery"
			|| lowerContent == "apple_boot"
			|| lowerContent == "apple_partition_map";
	}

	static bool IsMacOSXSystemMountPoint (const string &mountPoint)
	{
		return mountPoint == "/" || mountPoint.find ("/System/Volumes/") == 0;
	}

	static bool IsMacOSXAPFSSynthesizedDevice (const string &infoXml)
	{
		string containerReference;
		string filesystemType;
		string virtualOrPhysical;
		bool partitionMapPartition = false;
		bool wholeDisk = false;
		bool hasPartitionMapPartition = ExtractMacOSXPlistBool (infoXml, "PartitionMapPartition", partitionMapPartition);
		bool hasWholeDisk = ExtractMacOSXPlistBool (infoXml, "WholeDisk", wholeDisk);

		ExtractMacOSXPlistString (infoXml, "APFSContainerReference", containerReference);
		ExtractMacOSXPlistString (infoXml, "FilesystemType", filesystemType);
		ExtractMacOSXPlistString (infoXml, "VirtualOrPhysical", virtualOrPhysical);

		if (StringConverter::ToLower (virtualOrPhysical) == "virtual" && !containerReference.empty())
			return true;

		if (!ExtractMacOSXAPFSPhysicalStores (infoXml).empty() && hasPartitionMapPartition && !partitionMapPartition)
			return true;

		if (StringConverter::ToLower (filesystemType) == "apfs"
			&& hasPartitionMapPartition && !partitionMapPartition
			&& hasWholeDisk && !wholeDisk)
		{
			return true;
		}

		return false;
	}

	static bool IsMacOSXDeviceReadOnly (const string &infoXml)
	{
		bool value = false;
		// Writable and ReadOnlyVolume can reflect a read-only filesystem mount;
		// only media writability is fatal before unmounting.
		if (ExtractMacOSXPlistBool (infoXml, "ReadOnlyMedia", value) && value)
			return true;
		if (ExtractMacOSXPlistBool (infoXml, "WritableMedia", value) && !value)
			return true;

		return false;
	}

	static bool IsSelectedMacOSXSystemAPFSDevice (const string &selectedInfoXml, bool &wholeDiskSelected)
	{
		wholeDiskSelected = false;

		string selectedDeviceIdentifier;
		if (!ExtractMacOSXPlistString (selectedInfoXml, "DeviceIdentifier", selectedDeviceIdentifier) || selectedDeviceIdentifier.empty())
			return false;

		ExtractMacOSXPlistBool (selectedInfoXml, "WholeDisk", wholeDiskSelected);

		try
		{
			string rootInfoXml = GetMacOSXDiskutilInfo (VolumePath (FilesystemPath ("/")));
			list <string> rootStores = ExtractMacOSXAPFSPhysicalStores (rootInfoXml);

			foreach (const string &store, rootStores)
			{
				if (selectedDeviceIdentifier == store)
					return true;

				if (wholeDiskSelected)
				{
					try
					{
						string storeInfoXml = GetMacOSXDiskutilInfo (VolumePath (FilesystemPath (GetMacOSXRawDevicePath (store))));
						string storeParentWholeDisk;
						if (ExtractMacOSXPlistString (storeInfoXml, "ParentWholeDisk", storeParentWholeDisk)
							&& selectedDeviceIdentifier == storeParentWholeDisk)
						{
							return true;
						}
					}
					catch (...) { }
				}
			}
		}
		catch (...) { }

		return false;
	}

	static bool ValidateMacOSXSelectedDeviceForCreation (const VolumePath &devicePath)
	{
		string infoXml;
		try
		{
			infoXml = GetMacOSXDiskutilInfo (devicePath);
		}
		catch (...)
		{
			return true;
		}

		if (IsMacOSXAPFSSynthesizedDevice (infoXml))
		{
			wstring recommendedPath;
			list <string> stores = ExtractMacOSXAPFSPhysicalStores (infoXml);
			if (!stores.empty())
				recommendedPath = L" (" + StringConverter::ToWide (GetMacOSXRawDevicePath (stores.front())) + L")";

			Gui->ShowError (StringFormatter (LangString["MACOSX_APFS_SYNTHESIZED_DEVICE"], wstring (devicePath), recommendedPath));
			return false;
		}

		string content;
		if (ExtractMacOSXPlistString (infoXml, "Content", content) && IsMacOSXSystemSupportContent (content))
		{
			Gui->ShowError (StringFormatter (LangString["MACOSX_DEVICE_SYSTEM_PARTITION"], wstring (devicePath)));
			return false;
		}

		string mountPoint;
		if (ExtractMacOSXPlistString (infoXml, "MountPoint", mountPoint) && IsMacOSXSystemMountPoint (mountPoint))
		{
			Gui->ShowError (LangString["LINUX_ERROR_TRY_ENCRYPT_SYSTEM_PARTITION"]);
			return false;
		}

		bool selectedSystemWholeDisk = false;
		if (IsSelectedMacOSXSystemAPFSDevice (infoXml, selectedSystemWholeDisk))
		{
			if (selectedSystemWholeDisk)
				Gui->ShowError (LangString["LINUX_ERROR_TRY_ENCRYPT_SYSTEM_DRIVE"]);
			else
				Gui->ShowError (StringFormatter (LangString["MACOSX_APFS_SYSTEM_STORE"], wstring (devicePath)));

			return false;
		}

		if (IsMacOSXDeviceReadOnly (infoXml))
		{
			Gui->ShowError (StringFormatter (LangString["MACOSX_DEVICE_NOT_WRITABLE"], wstring (devicePath)));
			return false;
		}

		return true;
	}

	static void ShowMacOSXVolumeCreationError (const VolumePath &devicePath, const exception &e)
	{
		const SystemException *sysEx = dynamic_cast <const SystemException *> (&e);
		if (devicePath.IsDevice() && sysEx && sysEx->GetErrorCode() == EROFS)
		{
			Gui->ShowError (UserInterface::ExceptionToMessage (e) + L"\n\n" + LangString["MACOSX_APFS_EROFS_HINT"]);
			return;
		}

		Gui->ShowError (e);
	}

	bool VolumeCreationWizard::ProcessEvent(wxEvent& event)
	{
		if(GraphicUserInterface::HandlePasswordEntryCustomEvent (event))
			return true;
		else
			return WizardFrame::ProcessEvent(event);
	}
#endif

	VolumeCreationWizard::VolumeCreationWizard (wxWindow* parent)
		: WizardFrame (parent),
		CrossPlatformSupport (true),
		DisplayKeyInfo (false),
		LargeFilesSupport (false),
		QuickFormatEnabled (false),
		QuickFormatEnabledByWizard (false),
		SelectedFilesystemClusterSize (0),
		SelectedFilesystemType (VolumeCreationOptions::FilesystemType::FAT),
		SelectedVolumeHostType (VolumeHostType::File),
		SelectedVolumeType (VolumeType::Normal),
		Pim (0),
		OuterPim (0),
		SectorSize (0),
		VolumeSize (0)
	{
		RandomNumberGenerator::Start();

		SetTitle (LangString["INTRO_TITLE"]);
		SetImage (Resources::GetVolumeCreationWizardBitmap (Gui->GetCharHeight (this) * 21));
		SetMaxStaticTextWidth (55);
		
#ifdef TC_MACOSX
		GraphicUserInterface::InstallPasswordEntryCustomKeyboardShortcuts (this);
#endif

		SetStep (Step::VolumeHostType);

		class Timer : public wxTimer
		{
		public:
			Timer (VolumeCreationWizard *wizard) : Wizard (wizard) { }

			void Notify()
			{
				Wizard->OnRandomPoolUpdateTimer();
			}

			VolumeCreationWizard *Wizard;
		};

		RandomPoolUpdateTimer.reset (dynamic_cast <wxTimer *> (new Timer (this)));
		RandomPoolUpdateTimer->Start (200);
	}

	VolumeCreationWizard::~VolumeCreationWizard ()
	{
		burn (&Pim, sizeof (Pim));
		burn (&OuterPim, sizeof (OuterPim));
	}

	uint64 VolumeCreationWizard::GetSelectedVolumeFilesystemSize () const
	{
		if (OuterVolume || SelectedVolumeType != VolumeType::Hidden)
			return VolumeLayoutV2Normal().GetMaxDataSize (VolumeSize);

		return VolumeLayoutV2Hidden().GetMaxDataSize (VolumeSize);
	}

	WizardPage *VolumeCreationWizard::GetPage (WizardStep step)
	{
		switch (step)
		{
		case Step::VolumeHostType:
			{
				ClearHistory();

				OuterVolume = false;
				LargeFilesSupport = false;
				QuickFormatEnabled = false;
				QuickFormatEnabledByWizard = false;
				Pim = 0;

				SingleChoiceWizardPage <VolumeHostType::Enum> *page = new SingleChoiceWizardPage <VolumeHostType::Enum> (GetPageParent(), wxEmptyString, true);
				page->SetMinSize (wxSize (Gui->GetCharWidth (this) * 58, Gui->GetCharHeight (this) * 18 + 5));

				page->SetPageTitle (LangString["INTRO_TITLE"]);

				page->AddChoice (VolumeHostType::File, LangString["IDC_FILE_CONTAINER"], LangString["IDT_FILE_CONTAINER"], L"introcontainer", LangString["IDC_MORE_INFO_ON_CONTAINERS"]);
				page->AddChoice (VolumeHostType::Device, LangString["IDC_NONSYS_DEVICE"], LangString["IDT_NON_SYS_DEVICE"]);

				page->SetSelection (SelectedVolumeHostType);
				return page;
			}

		case Step::VolumeType:
			{
				SingleChoiceWizardPage <VolumeType::Enum> *page = new SingleChoiceWizardPage <VolumeType::Enum> (GetPageParent(), wxEmptyString, true);
				page->SetPageTitle (LangString["VOLUME_TYPE_TITLE"]);

				page->AddChoice (VolumeType::Normal, LangString["IDC_STD_VOL"], LangString["NORMAL_VOLUME_TYPE_HELP"]);
				page->AddChoice (VolumeType::Hidden, LangString["IDC_HIDDEN_VOL"], LangString["HIDDEN_VOLUME_TYPE_HELP"], L"hiddenvolume", LangString["IDC_HIDDEN_VOL_HELP"]);

				page->SetSelection (SelectedVolumeType);
				return page;
			}

		case Step::VolumeLocation:
			{
				VolumeLocationWizardPage *page = new VolumeLocationWizardPage (GetPageParent(), SelectedVolumeHostType);
				page->SetPageTitle (LangString["LOCATION"]);

				if (SelectedVolumeType == VolumeType::Hidden)
					page->SetPageText (LangString[SelectedVolumeHostType == VolumeHostType::File ? "FILE_HELP_HIDDEN_HOST_VOL" : "DEVICE_HELP_HIDDEN_HOST_VOL"]);
				else
					page->SetPageText (LangString[SelectedVolumeHostType == VolumeHostType::File ? "FILE_HELP" : "DEVICE_HELP_NO_INPLACE"]);

				page->SetVolumePath (SelectedVolumePath);
				return page;
			}

		case Step::EncryptionOptions:
			{
				EncryptionOptionsWizardPage *page = new EncryptionOptionsWizardPage (GetPageParent());

				if (OuterVolume)
					page->SetPageTitle (LangString["CIPHER_HIDVOL_HOST_TITLE"]);
				else if (SelectedVolumeType == VolumeType::Hidden)
					page->SetPageTitle (LangString["CIPHER_HIDVOL_TITLE"]);
				else
					page->SetPageTitle (LangString["CIPHER_TITLE"]);

				page->SetEncryptionAlgorithm (SelectedEncryptionAlgorithm);
				page->SetPkcs5Kdf (SelectedKdf);
				return page;
			}

		case Step::VolumeSize:
			{
				wxString freeSpaceText;
				wxString pageTitle;
				wxString pageText;

				if (OuterVolume)
				{
					pageTitle = LangString["SIZE_HIDVOL_HOST_TITLE"];
					pageText = LangString["SIZE_HELP_HIDDEN_HOST_VOL"];
				}
				else if (SelectedVolumeType == VolumeType::Hidden)
				{
					pageTitle = LangString["SIZE_HIDVOL_TITLE"];
					pageText = LangString["SIZE_HELP_HIDDEN_VOL"] + L"\n\n" + LangString["LINUX_DYNAMIC_NOTICE"];
					freeSpaceText = StringFormatter (LangString["LINUX_MAX_HIDDEN_SIZE"], Gui->SizeToString (MaxHiddenVolumeSize));
				}
				else
				{
					pageTitle = LangString["SIZE_TITLE"];
					pageText = LangString["VOLUME_SIZE_HELP"];
				}

				VolumeSizeWizardPage *page = new VolumeSizeWizardPage (GetPageParent(), SelectedVolumePath, SectorSize, freeSpaceText);

				page->SetPageTitle (pageTitle);
				page->SetPageText (pageText);

				if (!OuterVolume && SelectedVolumeType == VolumeType::Hidden)
					page->SetMaxVolumeSize (MaxHiddenVolumeSize);
				else
					page->SetVolumeSize (VolumeSize);

				if (OuterVolume)
					page->SetMinVolumeSize (TC_MIN_HIDDEN_VOLUME_HOST_SIZE);
				else if (SelectedVolumeType == VolumeType::Hidden)
					page->SetMinVolumeSize (TC_MIN_HIDDEN_VOLUME_SIZE);
				else
					page->SetMinVolumeSize (TC_MIN_VOLUME_SIZE);

				return page;
			}

		case Step::VolumePassword:
			{
				VolumePasswordWizardPage *page = new VolumePasswordWizardPage (GetPageParent(), Password, Keyfiles);
				page->EnableUsePim (); // force displaying "Use PIM"
				page->SetPimSelected (Pim > 0);

				if (OuterVolume)
					page->SetPageTitle (LangString["PASSWORD_HIDVOL_HOST_TITLE"]);
				else if (SelectedVolumeType == VolumeType::Hidden)
					page->SetPageTitle (LangString["PASSWORD_HIDVOL_TITLE"]);
				else
					page->SetPageTitle (LangString["PASSWORD_TITLE"]);

				page->SetPageText (LangString[OuterVolume ? "PASSWORD_HIDDENVOL_HOST_HELP" : "PASSWORD_HELP"]);
				return page;
			}

		case Step::VolumePim:
			{
				VolumePimWizardPage *page = new VolumePimWizardPage (GetPageParent());

				if (OuterVolume)
					page->SetPageTitle (LangString["PIM_HIDVOL_HOST_TITLE"]);
				else if (SelectedVolumeType == VolumeType::Hidden)
					page->SetPageTitle (LangString["PIM_HIDVOL_TITLE"]);
				else
					page->SetPageTitle (LangString["PIM_TITLE"]);

				page->SetPageText (LangString[SelectedKdf ? SelectedKdf->GetPimHelpMessageId() : "PIM_HELP"]);
				page->SetVolumePim (Pim);
				return page;
			}

		case Step::LargeFilesSupport:
			{
				SingleChoiceWizardPage <bool> *page = new SingleChoiceWizardPage <bool> (GetPageParent(), wxEmptyString, true);
				page->SetPageTitle (LangString["FILESYS_PAGE_TITLE"]);

				page->AddChoice (true, LangString["UISTR_YES"],LangString["FILESYS_PAGE_HELP_QUESTION"]);

				page->AddChoice (false, LangString["UISTR_NO"],LangString["FILESYS_PAGE_HELP_EXPLANATION"]);

				page->SetSelection (LargeFilesSupport);
				return page;
			}

		case Step::FormatOptions:
			{
				uint64 filesystemSize = GetSelectedVolumeFilesystemSize ();
				bool hiddenVolumeItself = !OuterVolume && SelectedVolumeType == VolumeType::Hidden;
				bool normalFileContainer = !OuterVolume && SelectedVolumeType == VolumeType::Normal && SelectedVolumeHostType == VolumeHostType::File;
				bool existingDeviceSupportedCase = SelectedVolumePath.IsDevice() && !hiddenVolumeItself;
				bool quickFormatSupported = existingDeviceSupportedCase || normalFileContainer;

				VolumeFormatOptionsWizardPage *page = new VolumeFormatOptionsWizardPage (GetPageParent(), filesystemSize, SectorSize,
					quickFormatSupported, OuterVolume, LargeFilesSupport);

				page->SetPageTitle (LangString["FORMAT_TITLE"]);
				page->SetFilesystemType (SelectedFilesystemType);

				if (hiddenVolumeItself)
				{
					QuickFormatEnabled = true;
					QuickFormatEnabledByWizard = true;
				}
				else
				{
					if (!quickFormatSupported || QuickFormatEnabledByWizard)
						QuickFormatEnabled = false;

					QuickFormatEnabledByWizard = false;
				}
				page->SetQuickFormat (QuickFormatEnabled);

				return page;
			}

		case Step::CrossPlatformSupport:
			{
				SingleChoiceWizardPage <bool> *page = new SingleChoiceWizardPage <bool> (GetPageParent(), wxEmptyString, true);
				page->SetPageTitle ( LangString["LINUX_CROSS_SUPPORT"]);

				page->AddChoice (true, LangString["LINUX_CROSS_SUPPORT_OTHER"], LangString["LINUX_CROSS_SUPPORT_OTHER_HELP"]);

				page->AddChoice (false, StringFormatter ( LangString["LINUX_CROSS_SUPPORT_ONLY"], SystemInfo::GetPlatformName()),
					LangString["LINUX_CROSS_SUPPORT_ONLY_HELP"]);

				page->SetSelection (CrossPlatformSupport);
				return page;
			}

		case Step::CreationProgress:
			{
				VolumeCreationProgressWizardPage *page = new VolumeCreationProgressWizardPage (GetPageParent(), DisplayKeyInfo);

				if (OuterVolume)
					page->SetPageTitle (LangString["FORMAT_HIDVOL_HOST_TITLE"]);
				else if (SelectedVolumeType == VolumeType::Hidden)
					page->SetPageTitle (LangString["FORMAT_HIDVOL_TITLE"]);
				else
					page->SetPageTitle (LangString["FORMAT_TITLE"]);

				page->SetPageText (LangString["FORMAT_HELP"]);
				page->AbortEvent.Connect (EventConnector <VolumeCreationWizard> (this, &VolumeCreationWizard::OnAbortButtonClick));
				page->SetNextButtonText (LangString["FORMAT"]);
				return page;
			}

		case Step::VolumeCreatedInfo:
			{
				InfoWizardPage *page = new InfoWizardPage (GetPageParent());
				page->SetPageTitle (LangString["FORMAT_FINISHED_TITLE"]);
				page->SetPageText (LangString["FORMAT_FINISHED_HELP"]);

				SetCancelButtonText (LangString["IDC_EXIT"]);
				return page;
			}

		case Step::OuterVolumeContents:
			{
				ClearHistory();

				MountOptions mountOptions;
				mountOptions.Keyfiles = Keyfiles;
				mountOptions.Password = Password;
				mountOptions.Pim = Pim;
				mountOptions.Path = make_shared <VolumePath> (SelectedVolumePath);

				try
				{
					wxBusyCursor busy;
					Gui->SetActiveFrame (this);
					MountedOuterVolume = Core->MountVolume (mountOptions);
				}
				catch (exception &e)
				{
					Gui->SetActiveFrame (this);
					Gui->ShowError (e);

					Close();
					return new InfoWizardPage (GetPageParent());
				}

				InfoWizardPage *page = new InfoWizardPage (GetPageParent(), LangString["LINUX_OPEN_OUTER_VOL"],
					shared_ptr <Functor> (new OpenOuterVolumeFunctor (MountedOuterVolume->MountPoint)));

				page->SetPageTitle (LangString["HIDVOL_HOST_FILLING_TITLE"]);

				page->SetPageText (StringFormatter (LangString["LINUX_OUTER_VOL_IS_MOUNTED"],
					wstring (MountedOuterVolume->MountPoint)));

				return page;
			}

		case Step::HiddenVolume:
			{
				ClearHistory();
				OuterVolume = false;
				LargeFilesSupport = false;
				Pim = 0;

				InfoWizardPage *page = new InfoWizardPage (GetPageParent());
				page->SetPageTitle (LangString["HIDVOL_PRE_CIPHER_TITLE"]);
				page->SetPageText (LangString["HIDVOL_PRE_CIPHER_HELP"]);

				return page;
			}

		default:
			throw ParameterIncorrect (SRC_POS);
		}
	}

	void VolumeCreationWizard::OnAbortButtonClick (EventArgs &args)
	{
		AbortRequested = true;
	}

	void VolumeCreationWizard::OnMouseMotion (wxMouseEvent& event)
	{
		event.Skip();
		if (!IsWorkInProgress() && RandomNumberGenerator::IsRunning())
		{
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <uint8 *> (&event), sizeof (event)));

			long coord = event.GetX();
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <uint8 *> (&coord), sizeof (coord)));
			coord = event.GetY();
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <uint8 *> (&coord), sizeof (coord)));

			VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());
			if (page)
			{
				page->IncrementEntropyProgress ();
			}
		}
	}

	void VolumeCreationWizard::OnProgressTimer ()
	{
		if (!IsWorkInProgress())
			return;

		if (AbortRequested && !AbortConfirmationPending)
		{
			AbortConfirmationPending = true;
			if (Gui->AskYesNo (LangString ["FORMAT_ABORT"], true))
			{
				if (IsWorkInProgress() && Creator.get() != nullptr)
				{
					CreationAborted = true;
					Creator->Abort();
				}
			}
			AbortRequested = false;
			AbortConfirmationPending = false;
		}

		VolumeCreator::ProgressInfo progress = Creator->GetProgressInfo();

		VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());
		if (page)
		{
			page->SetProgressStage (progress.Stage);
			page->SetProgressValue (progress.SizeDone);
		}

		if (!progress.CreationInProgress && !AbortConfirmationPending)
		{
			OnVolumeCreatorFinished ();
		}
	}

	void VolumeCreationWizard::OnRandomPoolUpdateTimer ()
	{
		if (!IsWorkInProgress())
		{
			wxLongLong time = wxGetLocalTimeMillis();
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <uint8 *> (&time), sizeof (time)));
		}
	}

	void VolumeCreationWizard::SetCreationProgressText (const wxString &text)
	{
		VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());
		if (!page)
			return;

		page->SetPageText (text);
		page->Refresh();
		page->Update();
		Gui->Yield();
	}

	void VolumeCreationWizard::OnVolumeCreatorFinished ()
	{
		VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());

		ProgressTimer.reset();
		if (page)
		{
			page->SetProgressState (false);
			page->EnableAbort (false);
		}
		bool workInProgressCleared = false;

		try
		{
			if (!CreationAborted)
			{
				Creator->CheckResult();

#ifdef TC_UNIX
				// Format non-FAT filesystem
				const char *fsFormatter = VolumeCreationOptions::FilesystemType::GetFsFormatter (SelectedFilesystemType);

				if (fsFormatter)
				{
					wxBusyCursor busy;

					SetCreationProgressText (LangString["FORMAT_STAGE_PREPARING_TEMP_VOLUME"]);

					MountOptions mountOptions (Gui->GetPreferences().DefaultMountOptions);
					mountOptions.Path = make_shared <VolumePath> (SelectedVolumePath);
					mountOptions.NoFilesystem = true;
					mountOptions.Protection = VolumeProtection::None;
					mountOptions.Password = Password;
					mountOptions.Pim = Pim;
					mountOptions.Keyfiles = Keyfiles;
					mountOptions.Kdf = Kdf;

					shared_ptr <VolumeInfo> volume = Core->MountVolume (mountOptions);
					finally_do_arg (shared_ptr <VolumeInfo>, volume, { Core->DismountVolume (finally_arg, true); });

					shared_ptr <VolumeLayout> layout((volume->Type == VolumeType::Normal)? (VolumeLayout*) new VolumeLayoutV2Normal() : (VolumeLayout*) new VolumeLayoutV2Hidden());
					uint64 filesystemSize = layout->GetMaxDataSize (VolumeSize);

					SetCreationProgressText (LangString["FORMAT_STAGE_PREPARING_TEMP_DEVICE"]);
					Thread::Sleep (2000);	// Try to prevent race conditions caused by OS

					// Temporarily take ownership of the device if the user is not an administrator
					DevicePath virtualDevice = volume->VirtualDevice;
#ifdef TC_MACOSX
					string virtualDeviceStr = virtualDevice;
					virtualDevice = GetMacOSXRawDevicePath (virtualDeviceStr);

					MacOSXFormatterDeviceOwnerRestoreList changedDeviceOwners;
					finally_do_arg (MacOSXFormatterDeviceOwnerRestoreList *, &changedDeviceOwners,
					{
						RestoreMacOSXFormatterDeviceOwners (*finally_arg);
					});
					bool useElevatedAPFSFormatter = UseElevatedMacOSXAPFSFormatter (fsFormatter);
					if (!useElevatedAPFSFormatter)
						PrepareMacOSXFormatterDevice (virtualDevice, changedDeviceOwners);
#else
					UserId origDeviceOwner ((uid_t) -1);

					try
					{
						File file;
						file.Open (virtualDevice, File::OpenReadWrite);
					}
					catch (...)
					{
						if (!Core->HasAdminPrivileges())
						{
							origDeviceOwner = virtualDevice.GetOwner();
							Core->SetFileOwner (virtualDevice, UserId (getuid()));
						}
					}

					finally_do_arg2 (FilesystemPath, virtualDevice, UserId, origDeviceOwner,
					{
						if (finally_arg2.SystemId != (uid_t) -1)
							Core->SetFileOwner (finally_arg, finally_arg2);
					});
#endif

					// Create filesystem
					list <string> args;

					if (SelectedFilesystemType == VolumeCreationOptions::FilesystemType::MacOsExt && VolumeSize >= 10 * BYTES_PER_MB)
						args.push_back ("-J");

					// Perform a quick NTFS formatting
					if (SelectedFilesystemType == VolumeCreationOptions::FilesystemType::NTFS)
						args.push_back ("-f");

					if (SelectedFilesystemType == VolumeCreationOptions::FilesystemType::Btrfs)
					{
						args.push_back ("-f");
						if (filesystemSize < VC_MIN_LARGE_BTRFS_VOLUME_SIZE)
						{
							// use mixed mode for small BTRFS volumes
							args.push_back ("-M");
						}
					}

#ifdef TC_MACOSX
					if (IsMacOSXExFATFormatter (fsFormatter))
						AddMacOSXExFATFormatterArgs (args);

					if (IsMacOSXAPFSFormatter (fsFormatter) && !useElevatedAPFSFormatter)
						AddMacOSXAPFSFormatterUserArgs (args);
#endif

					args.push_back (string (virtualDevice));

					SetCreationProgressText (StringFormatter (LangString["FORMAT_STAGE_CREATING_FILESYSTEM"], fsFormatter));
#ifdef TC_MACOSX
					ExecuteMacOSXFilesystemFormatter (fsFormatter, args);
#else
					Process::Execute (fsFormatter, args);
#endif
					SetCreationProgressText (LangString["FORMAT_STAGE_DISMOUNTING_TEMP_VOLUME"]);
				}
#endif // TC_UNIX

				Gui->EndInteractiveBusyState (this);
				SetWorkInProgress (false);
				workInProgressCleared = true;

				if (OuterVolume)
				{
					SetStep (Step::OuterVolumeContents);
				}
				else
				{
					Gui->ShowInfo (SelectedVolumeType == VolumeType::Hidden ? "HIDVOL_FORMAT_FINISHED_HELP" : "FORMAT_FINISHED_INFO");
					SetStep (Step::VolumeCreatedInfo);
				}

				return;
			}
		}
		catch (exception &e)
		{
			if (!workInProgressCleared)
			{
				Gui->EndInteractiveBusyState (this);
				SetWorkInProgress (false);
				workInProgressCleared = true;
			}
#ifdef TC_MACOSX
			ShowMacOSXVolumeCreationError (SelectedVolumePath, e);
#else
			Gui->ShowError (e);
#endif
		}

		if (!workInProgressCleared)
		{
			Gui->EndInteractiveBusyState (this);
			SetWorkInProgress (false);
		}

		if (page)
			page->SetProgressValue (0);

		if (SelectedVolumeType == VolumeType::Normal && !SelectedVolumePath.IsDevice())
		{
			try
			{
				FilePath (wstring (SelectedVolumePath)).Delete();
			}
			catch (...) { }
		}
	}

	WizardFrame::WizardStep VolumeCreationWizard::ProcessPageChangeRequest (bool forward)
	{
		switch (GetCurrentStep())
		{
		case Step::VolumeHostType:
			{
				SingleChoiceWizardPage <VolumeHostType::Enum> *page = dynamic_cast <SingleChoiceWizardPage <VolumeHostType::Enum> *> (GetCurrentPage());

				try
				{
					SelectedVolumeHostType = page->GetSelection();
				}
				catch (NoItemSelected &)
				{
					return GetCurrentStep();
				}

				return Step::VolumeType;
			}

		case Step::VolumeType:
			{
				SingleChoiceWizardPage <VolumeType::Enum> *page = dynamic_cast <SingleChoiceWizardPage <VolumeType::Enum> *> (GetCurrentPage());

				try
				{
					SelectedVolumeType = page->GetSelection();
				}
				catch (NoItemSelected &)
				{
					return GetCurrentStep();
				}

				if (SelectedVolumeType == VolumeType::Hidden)
					OuterVolume = true;

				return Step::VolumeLocation;
			}

		case Step::VolumeLocation:
			{
				VolumeLocationWizardPage *page = dynamic_cast <VolumeLocationWizardPage *> (GetCurrentPage());
				SelectedVolumePath = page->GetVolumePath();
				VolumeSize = 0;

				if (forward)
				{
					if (Core->IsVolumeMounted (SelectedVolumePath))
					{
						Gui->ShowInfo ("UNMOUNT_FIRST");
						return GetCurrentStep();
					}

					if (SelectedVolumePath.IsDevice())
					{
						if (!DeviceWarningConfirmed && !Gui->AskYesNo (LangString["FORMAT_DEVICE_FOR_ADVANCED_ONLY"]))
							return GetCurrentStep();

						DeviceWarningConfirmed = true;

#ifdef TC_MACOSX
						if (!ValidateMacOSXSelectedDeviceForCreation (SelectedVolumePath))
							return GetCurrentStep();
#endif

						foreach_ref (const HostDevice &drive, Core->GetHostDevices())
						{
							bool selectedWholeDevice = drive.Path == SelectedVolumePath;
#ifdef TC_MACOSX
							selectedWholeDevice = selectedWholeDevice
								|| IsSameMacOSXDevicePath (string (drive.Path), string (SelectedVolumePath));
#endif
							if (selectedWholeDevice && !drive.Partitions.empty())
							{
								foreach_ref (const HostDevice &partition, drive.Partitions)
								{
									if (partition.MountPoint == "/")
									{
										Gui->ShowError (LangString["LINUX_ERROR_TRY_ENCRYPT_SYSTEM_DRIVE"]);
										return GetCurrentStep();
									}
								}

								Gui->ShowError ("DEVICE_PARTITIONS_ERR");
								return GetCurrentStep();
							}
						}

						try
						{
							SectorSize = Core->GetDeviceSectorSize (SelectedVolumePath);
							VolumeSize = Core->GetDeviceSize (SelectedVolumePath);
						}
						catch (UserAbort&)
						{
							return Step::VolumeLocation;
						}
						catch (exception &e)
						{
							Gui->ShowError (e);
							Gui->ShowError ("CANNOT_CALC_SPACE");
							return GetCurrentStep();
						}

						DirectoryPath mountPoint;
						try
						{
							mountPoint = Core->GetDeviceMountPoint (SelectedVolumePath);

							if (!mountPoint.IsEmpty())
							{
								if (mountPoint == "/")
								{
									Gui->ShowError (LangString["LINUX_ERROR_TRY_ENCRYPT_SYSTEM_PARTITION"]);
									return GetCurrentStep();
								}

								if (!Gui->AskYesNo (StringFormatter (LangString["LINUX_WARNING_FORMAT_DESTROY_FS"], wstring (mountPoint)), false, true))
									return GetCurrentStep();

								try
								{
									Core->DismountFilesystem (mountPoint, true);
								}
								catch (exception &e)
								{
									Gui->ShowError (e);
									Gui->ShowError (StringFormatter (LangString["LINUX_MOUNTET_HINT"], wstring (mountPoint)));
									return GetCurrentStep();
								}
							}
						}
						catch (...) { }
					}
					else
						SectorSize = TC_SECTOR_SIZE_FILE_HOSTED_VOLUME;
				}

				return Step::EncryptionOptions;
			}

		case Step::EncryptionOptions:
			{
				EncryptionOptionsWizardPage *page = dynamic_cast <EncryptionOptionsWizardPage *> (GetCurrentPage());
				SelectedEncryptionAlgorithm = page->GetEncryptionAlgorithm ();
				SelectedKdf = page->GetPkcs5Kdf ();

				if (forward)
					RandomNumberGenerator::SetHash (SelectedKdf->GetHash());

				if (SelectedVolumePath.IsDevice() && (OuterVolume || SelectedVolumeType != VolumeType::Hidden))
					return Step::VolumePassword;
				else
					return Step::VolumeSize;
			}

		case Step::VolumeSize:
			{
				VolumeSizeWizardPage *page = dynamic_cast <VolumeSizeWizardPage *> (GetCurrentPage());

				try
				{
					VolumeSize = page->GetVolumeSize();
				}
				catch (Exception &e)
				{
					if (forward)
					{
						Gui->ShowError (e);
						return GetCurrentStep();
					}
				}

				if (forward
					&& !OuterVolume && SelectedVolumeType == VolumeType::Hidden
					&& (double) VolumeSize / MaxHiddenVolumeSize > 0.85)
				{
					if (!Gui->AskYesNo (LangString["FREE_SPACE_FOR_WRITING_TO_OUTER_VOLUME"]))
						return GetCurrentStep();
				}

				if (forward
					&& SelectedVolumeHostType == VolumeHostType::File
					&& VolumeSize > 4 * BYTES_PER_GB
					&& (OuterVolume || SelectedVolumeType != VolumeType::Hidden)
					&& !Core->FilesystemSupportsLargeFiles (SelectedVolumePath))
				{
					Gui->ShowWarning (LangString["VOLUME_TOO_LARGE_FOR_FAT32"]);
				}

				return Step::VolumePassword;
			}

		case Step::VolumePassword:
			{
				VolumePasswordWizardPage *page = dynamic_cast <VolumePasswordWizardPage *> (GetCurrentPage());
				try
				{
					Password = page->GetPassword();
				}
				catch (PasswordException& e)
				{
					Gui->ShowWarning (e);
					return GetCurrentStep();
				}

				Kdf = page->GetPkcs5Kdf();
				Keyfiles = page->GetKeyfiles();

				if (forward && Password && !Password->IsEmpty())
				{
					if (Password->Size() < VolumePassword::WarningSizeThreshold)
					{
						if (!Gui->AskYesNo (LangString["PASSWORD_LENGTH_WARNING"], false, true))
						{
							return GetCurrentStep();
						}
					}
				}

				if (page->IsPimSelected ())
					return Step::VolumePim;
				else
				{
					// Clear PIM
					Pim = 0;

					if (forward && !OuterVolume && SelectedVolumeType == VolumeType::Hidden)
					{
						shared_ptr <VolumePassword> hiddenPassword;
						try
						{
							hiddenPassword = Keyfile::ApplyListToPassword (Keyfiles, Password, Gui->GetPreferences().EMVSupportEnabled);
						}
						catch (...)
						{
							hiddenPassword = Password;
						}

						// check if Outer and Hidden passwords are the same
						if ( 	(hiddenPassword && !hiddenPassword->IsEmpty() && OuterPassword && !OuterPassword->IsEmpty() && (*(OuterPassword.get()) == *(hiddenPassword.get())))
							||
								((!hiddenPassword || hiddenPassword->IsEmpty()) && (!OuterPassword || OuterPassword->IsEmpty()))
							)
						{
							//check if they have also the same PIM
							if (OuterPim == Pim)
							{
								Gui->ShowError (LangString["LINUX_HIDDEN_PASS_NO_DIFF"]);
								return GetCurrentStep();
							}
						}
					}

					uint64 filesystemSize = GetSelectedVolumeFilesystemSize ();
					if (filesystemSize > 4 * BYTES_PER_GB)
					{
						if (filesystemSize <= TC_MAX_FAT_SECTOR_COUNT * (uint64) SectorSize)
							return Step::LargeFilesSupport;
						else
							SelectedFilesystemType = VolumeCreationOptions::FilesystemType::GetPlatformNative();
					}

					return Step::FormatOptions;
				}
			}

		case Step::VolumePim:
			{
				VolumePimWizardPage *page = dynamic_cast <VolumePimWizardPage *> (GetCurrentPage());
				Pim = page->GetVolumePim();

				if (-1 == Pim)
				{
					// PIM invalid: don't go anywhere
					Gui->ShowError ("PIM_TOO_BIG");
					return GetCurrentStep();
				}

				if (forward && !OuterVolume && SelectedVolumeType == VolumeType::Hidden)
				{
					shared_ptr <VolumePassword> hiddenPassword;
					try
					{
						hiddenPassword = Keyfile::ApplyListToPassword (Keyfiles, Password, Gui->GetPreferences().EMVSupportEnabled);
					}
					catch (...)
					{
						hiddenPassword = Password;
					}

					// check if Outer and Hidden passwords are the same
					if ( 	(hiddenPassword && !hiddenPassword->IsEmpty() && OuterPassword && !OuterPassword->IsEmpty() && (*(OuterPassword.get()) == *(hiddenPassword.get())))
						||
							((!hiddenPassword || hiddenPassword->IsEmpty()) && (!OuterPassword || OuterPassword->IsEmpty()))
						)
					{
						//check if they have also the same PIM
						if (OuterPim == Pim)
						{
							Gui->ShowError (LangString["LINUX_HIDDEN_PASS_NO_DIFF"]);
							return GetCurrentStep();
						}
					}
				}

				if (forward && Password && !Password->IsEmpty())
				{
					if (!SelectedKdf)
					{
						Gui->ShowError ("PARAMETER_INCORRECT");
						return GetCurrentStep();
					}

					if (Password->Size() < VolumePassword::SmallPimPasswordSizeThreshold)
					{
						if (Pim > 0 && Pim < SelectedKdf->GetDefaultPim())
						{
							Gui->ShowError (SelectedKdf->GetPimRequireLongPasswordMessageId());
							return GetCurrentStep();
						}
					}
					else if (Pim > 0 && Pim < SelectedKdf->GetDefaultPim())
					{
						if (!Gui->AskYesNo (LangString[SelectedKdf->GetPimSmallWarningMessageId()], false, true))
						{
							return GetCurrentStep();
						}
					}
				}

				uint64 filesystemSize = GetSelectedVolumeFilesystemSize ();
				if (filesystemSize > 4 * BYTES_PER_GB)
				{
					if (filesystemSize <= TC_MAX_FAT_SECTOR_COUNT * (uint64) SectorSize)
						return Step::LargeFilesSupport;
					else
						SelectedFilesystemType = VolumeCreationOptions::FilesystemType::GetPlatformNative();
				}

				return Step::FormatOptions;
			}

		case Step::LargeFilesSupport:
			{
				SingleChoiceWizardPage <bool> *page = dynamic_cast <SingleChoiceWizardPage <bool> *> (GetCurrentPage());

				try
				{
					LargeFilesSupport = page->GetSelection();
				}
				catch (NoItemSelected &)
				{
					return GetCurrentStep();
				}

				if (LargeFilesSupport)
					SelectedFilesystemType = VolumeCreationOptions::FilesystemType::GetPlatformNative();
				else
					SelectedFilesystemType = VolumeCreationOptions::FilesystemType::FAT;

				return Step::FormatOptions;
			}

		case Step::FormatOptions:
			{
				VolumeFormatOptionsWizardPage *page = dynamic_cast <VolumeFormatOptionsWizardPage *> (GetCurrentPage());

				if (forward && OuterVolume)
				{
					if (page->GetFilesystemType() != VolumeCreationOptions::FilesystemType::FAT)
					{
						if (!Gui->AskYesNo (LangString["LINUX_CONFIRM_INNER_VOLUME_CALC"], false, true))
						{
							return GetCurrentStep();
						}
					}
				}

				SelectedFilesystemType = page->GetFilesystemType();
				QuickFormatEnabled = page->IsQuickFormatEnabled();
				QuickFormatEnabledByWizard = !OuterVolume && SelectedVolumeType == VolumeType::Hidden;

				if (SelectedFilesystemType != VolumeCreationOptions::FilesystemType::None
					&& SelectedFilesystemType != VolumeCreationOptions::FilesystemType::FAT)
					return Step::CrossPlatformSupport;

				return Step::CreationProgress;
			}

		case Step::CrossPlatformSupport:
			{
				SingleChoiceWizardPage <bool> *page = dynamic_cast <SingleChoiceWizardPage <bool> *> (GetCurrentPage());

				try
				{
					CrossPlatformSupport = page->GetSelection();
				}
				catch (NoItemSelected &)
				{
					return GetCurrentStep();
				}

				if (forward && CrossPlatformSupport)
					Gui->ShowWarning (StringFormatter (LangString["LINUX_NOT_FAT_HINT"], SystemInfo::GetPlatformName()));

				return Step::CreationProgress;
			}

		case Step::CreationProgress:
			{
				VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());

				DisplayKeyInfo = page->IsKeyInfoDisplayed();

				if (forward)
				{
					if (SelectedVolumeType != VolumeType::Hidden || OuterVolume)
					{
						if (SelectedFilesystemType == VolumeCreationOptions::FilesystemType::FAT)
						{
							uint64 filesystemSize = GetSelectedVolumeFilesystemSize ();
							if (filesystemSize > TC_MAX_FAT_SECTOR_COUNT * (uint64) SectorSize)
							{
								Gui->ShowError (LangString["FAT_NOT_AVAILABLE_FOR_SO_LARGE_VOLUME"]);
								return GetCurrentStep();
							}
						}

						if (SelectedVolumePath.IsDevice())
						{
							wxString confirmMsg = LangString["OVERWRITEPROMPT_DEVICE"];

							if (!Gui->AskYesNo (wxString::Format (confirmMsg, wxString (LangString["DEVICE"]).c_str(), wstring (SelectedVolumePath).c_str(), L""), false, true))
								return GetCurrentStep();
						}
						else if (FilesystemPath (wstring (SelectedVolumePath)).IsFile())
						{
							wxString confirmMsg = LangString["OVERWRITEPROMPT"];

							if (!Gui->AskYesNo (wxString::Format (confirmMsg, wstring (SelectedVolumePath).c_str()), false, true))
								return GetCurrentStep();
						}
					}

					AbortRequested = false;
					AbortConfirmationPending = false;
					CreationAborted = false;
					SetWorkInProgress (true);
					UpdateControls();

					Gui->BeginInteractiveBusyState (this);

					try
					{
						make_shared_auto (VolumeCreationOptions, options);

						options->Filesystem = SelectedFilesystemType;
						options->FilesystemClusterSize = SelectedFilesystemClusterSize;
						options->SectorSize = SectorSize;
						options->EA = SelectedEncryptionAlgorithm;
						options->Password = Password;
						options->Pim = Pim;
						options->Keyfiles = Keyfiles;
						options->Path = SelectedVolumePath;
						options->Quick = QuickFormatEnabled;
						options->Size = VolumeSize;
						options->Type = OuterVolume ? VolumeType::Normal : SelectedVolumeType;
						options->VolumeHeaderKdf = SelectedKdf;
						options->EMVSupportEnabled = Gui->GetPreferences().EMVSupportEnabled;


						Creator.reset (new VolumeCreator);
						VolumeCreatorThreadRoutine routine(options, Creator);
						Gui->ExecuteWaitThreadRoutine (this, &routine);

						page->SetKeyInfo (Creator->GetKeyInfo());

						class Timer : public wxTimer
						{
						public:
							Timer (VolumeCreationWizard *wizard) : Wizard (wizard) { }

							void Notify()
							{
								Wizard->OnProgressTimer();
							}

							VolumeCreationWizard *Wizard;
						};

						page->SetProgressRange (options->Size);
						page->SetProgressState (true);
						ProgressTimer.reset (dynamic_cast <wxTimer *> (new Timer (this)));
						ProgressTimer->Start (50);
					}
					catch (Exception &e)
					{
						CreationAborted = true;
						OnVolumeCreatorFinished();
#ifdef TC_MACOSX
						ShowMacOSXVolumeCreationError (SelectedVolumePath, e);
#else
						Gui->ShowError (e);
#endif
					}
				}

				return GetCurrentStep();
			}

		case Step::VolumeCreatedInfo:
			Creator.reset();
			SetCancelButtonText (L"");

			// clear saved credentials
			Password.reset();
			OuterPassword.reset();
			burn (&Pim, sizeof (Pim));
			burn (&OuterPim, sizeof (OuterPim));

			return Step::VolumeHostType;

		case Step::OuterVolumeContents:
			try
			{
				// Determine maximum size of the hidden volume. Scan cluster table offline as a live filesystem test would
				// require using FUSE and loop device which cannot be used for devices with sectors larger than 512.

				wxBusyCursor busy;
				bool outerVolumeAvailableSpaceValid = false;
				uint64 outerVolumeAvailableSpace = 0;
				MaxHiddenVolumeSize = 0;

				Gui->SetActiveFrame (this);

				if (MountedOuterVolume)
				{
#ifdef TC_UNIX
					const DirectoryPath &outerVolumeMountPoint = MountedOuterVolume->MountPoint;
					struct statvfs stat;
					if (statvfs(((string)outerVolumeMountPoint).c_str(), &stat) == 0)
					{
						uint64 blockSize = (uint64) stat.f_frsize;
						if (blockSize == 0)
							blockSize = (uint64) stat.f_bsize;

						if (blockSize != 0)
						{
							outerVolumeAvailableSpace = blockSize * (uint64) stat.f_bavail;
							outerVolumeAvailableSpaceValid = true;
						}
					}
#endif
					Core->DismountVolume (MountedOuterVolume);
					MountedOuterVolume.reset();
				}

#ifdef TC_UNIX
				// Temporarily take ownership of a device if the user is not an administrator
				UserId origDeviceOwner ((uid_t) -1);

				if (!Core->HasAdminPrivileges() && SelectedVolumePath.IsDevice())
				{
					origDeviceOwner = FilesystemPath (wstring (SelectedVolumePath)).GetOwner();
					Core->SetFileOwner (SelectedVolumePath, UserId (getuid()));
				}

				finally_do_arg2 (FilesystemPath, SelectedVolumePath, UserId, origDeviceOwner,
				{
					if (finally_arg2.SystemId != (uid_t) -1)
						Core->SetFileOwner (finally_arg, finally_arg2);
				});
#endif

				shared_ptr <Volume> outerVolume = Core->OpenVolume (make_shared <VolumePath> (SelectedVolumePath), true, Password, Pim, Kdf, Keyfiles, VolumeProtection::ReadOnly);
				uint64 outerVolumeDataSize = outerVolume->GetSize();
				try
				{
					MaxHiddenVolumeSize = Core->GetMaxHiddenVolumeSize (outerVolume);
				}
				catch (ParameterIncorrect& )
				{
					// Outer volume not using FAT
					// estimate maximum hidden volume size as 80% of available size of outer volume
					if (outerVolumeAvailableSpaceValid)
					{
						if (outerVolumeAvailableSpace > outerVolumeDataSize)
							outerVolumeAvailableSpace = outerVolumeDataSize;

						MaxHiddenVolumeSize = (outerVolumeAvailableSpace / 5ULL) * 4ULL
							+ ((outerVolumeAvailableSpace % 5ULL) * 4ULL) / 5ULL;
					}
					else
						throw;
				}

				if (MaxHiddenVolumeSize > outerVolumeDataSize)
					MaxHiddenVolumeSize = outerVolumeDataSize;

				// Add a reserve (in case the user mounts the outer volume and creates new files
				// on it by accident or OS writes some new data behind his or her back, such as
				// System Restore etc.)

				uint64 reservedSize = outerVolumeDataSize / 200;
				if (reservedSize > 10 * BYTES_PER_MB)
					reservedSize = 10 * BYTES_PER_MB;

				if (MaxHiddenVolumeSize < reservedSize)
					MaxHiddenVolumeSize = 0;
				else
					MaxHiddenVolumeSize -= reservedSize;

				MaxHiddenVolumeSize -= MaxHiddenVolumeSize % outerVolume->GetSectorSize();		// Must be a multiple of the sector size

				// remember Outer password and keyfiles in order to be able to compare it with those of Hidden volume
				try
				{
					OuterPassword = Keyfile::ApplyListToPassword (Keyfiles, Password, Gui->GetPreferences().EMVSupportEnabled);
				}
				catch (...)
				{
					OuterPassword = Password;
				}

				OuterPim = Pim;
			}
			catch (exception &e)
			{
				Gui->SetActiveFrame (this);
				Gui->ShowError (e);
				return GetCurrentStep();
			}

			return Step::HiddenVolume;

		case Step::HiddenVolume:
			return Step::EncryptionOptions;

		default:
			throw ParameterIncorrect (SRC_POS);
		}
	}

	void VolumeCreationWizard::UpdateControls ()
	{
		VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());
		if (page)
		{
			page->EnableAbort (IsWorkInProgress());
		}
	}

	bool VolumeCreationWizard::DeviceWarningConfirmed;
}
