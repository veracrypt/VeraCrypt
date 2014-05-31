/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Platform/SystemInfo.h"
#ifdef TC_UNIX
#include <unistd.h>
#include "Platform/Unix/Process.h"
#endif
#include "Core/RandomNumberGenerator.h"
#include "Core/VolumeCreator.h"
#include "Main/Application.h"
#include "Main/GraphicUserInterface.h"
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
#include "VolumeSizeWizardPage.h"

namespace TrueCrypt
{
	VolumeCreationWizard::VolumeCreationWizard (wxWindow* parent)
		: WizardFrame (parent),
		CrossPlatformSupport (true),
		DisplayKeyInfo (true),
		LargeFilesSupport (false),
		QuickFormatEnabled (false),
		SelectedFilesystemClusterSize (0),
		SelectedFilesystemType (VolumeCreationOptions::FilesystemType::FAT),
		SelectedVolumeHostType (VolumeHostType::File),
		SelectedVolumeType (VolumeType::Normal),
		SectorSize (0),
		VolumeSize (0)
	{
		RandomNumberGenerator::Start();

		SetTitle (LangString["INTRO_TITLE"]);
		SetImage (Resources::GetVolumeCreationWizardBitmap (Gui->GetCharHeight (this) * 21));
		SetMaxStaticTextWidth (55);

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

				SingleChoiceWizardPage <VolumeHostType::Enum> *page = new SingleChoiceWizardPage <VolumeHostType::Enum> (GetPageParent(), wxEmptyString, true);
				page->SetMinSize (wxSize (Gui->GetCharWidth (this) * 58, Gui->GetCharHeight (this) * 18 + 5));

				page->SetPageTitle (LangString["INTRO_TITLE"]);

				page->AddChoice (VolumeHostType::File, LangString["IDC_FILE_CONTAINER"], LangString["IDT_FILE_CONTAINER"], L"introcontainer", LangString["IDC_MORE_INFO_ON_CONTAINERS"]);
				page->AddChoice (VolumeHostType::Device, _("Create a volume within a partition/&drive"), _("Formats and encrypts a non-system partition, entire external or secondary drive, entire USB stick, etc."));

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
				page->SetPageTitle (LangString["VOLUME_LOCATION"]);

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
				page->SetHash (SelectedHash);
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
					pageText = LangString["SIZE_HELP_HIDDEN_VOL"] + L"\n\n" + _("Please note that if your operating system does not allocate files from the beginning of the free space, the maximum possible hidden volume size may be much smaller than the size of the free space on the outer volume. This not a bug in VeraCrypt but a limitation of the operating system.");
					freeSpaceText = StringFormatter (_("Maximum possible hidden volume size for this volume is {0}."), Gui->SizeToString (MaxHiddenVolumeSize));
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
				
				if (OuterVolume)
					page->SetPageTitle (LangString["PASSWORD_HIDVOL_HOST_TITLE"]);
				else if (SelectedVolumeType == VolumeType::Hidden)
					page->SetPageTitle (LangString["PASSWORD_HIDVOL_TITLE"]);
				else
					page->SetPageTitle (LangString["PASSWORD_TITLE"]);
				
				page->SetPageText (LangString[OuterVolume ? "PASSWORD_HIDDENVOL_HOST_HELP" : "PASSWORD_HELP"]);
				return page;
			}

		case Step::LargeFilesSupport:
			{
				SingleChoiceWizardPage <bool> *page = new SingleChoiceWizardPage <bool> (GetPageParent(), wxEmptyString, true);
				page->SetPageTitle (LangString["FILESYS_PAGE_TITLE"]);

				page->AddChoice (false, _("I will not store files larger than 4 GB on the volume"),
					_("Choose this option if you do not need to store files larger than 4 GB (4,294,967,296 bytes) on the volume."));

				page->AddChoice (true, _("I will store files larger than 4 GB on the volume"),
					_("Choose this option if you need to store files larger than 4 GB (4,294,967,296 bytes) on the volume."));

				page->SetSelection (LargeFilesSupport);
				return page;
			}

		case Step::FormatOptions:
			{
				VolumeFormatOptionsWizardPage *page = new VolumeFormatOptionsWizardPage (GetPageParent(), VolumeSize, SectorSize,
					SelectedVolumePath.IsDevice() && (OuterVolume || SelectedVolumeType != VolumeType::Hidden), OuterVolume, LargeFilesSupport);

				page->SetPageTitle (_("Format Options"));
				page->SetFilesystemType (SelectedFilesystemType);
				
				if (!OuterVolume && SelectedVolumeType == VolumeType::Hidden)
					QuickFormatEnabled = true;
				page->SetQuickFormat (QuickFormatEnabled);

				return page;
			}
			
		case Step::CrossPlatformSupport:
			{
				SingleChoiceWizardPage <bool> *page = new SingleChoiceWizardPage <bool> (GetPageParent(), wxEmptyString, true);
				page->SetPageTitle (_("Cross-Platform Support"));

				page->AddChoice (true, _("I will mount the volume on other platforms"),
					_("Choose this option if you need to use the volume on other platforms."));

				page->AddChoice (false, StringFormatter (_("I will mount the volume only on {0}"), SystemInfo::GetPlatformName()),
					_("Choose this option if you do not need to use the volume on other platforms."));

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
				
				SetCancelButtonText (_("Exit"));
				return page;
			}

		case Step::OuterVolumeContents:
			{
				ClearHistory();

				MountOptions mountOptions;
				mountOptions.Keyfiles = Keyfiles;
				mountOptions.Password = Password;
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
				
				struct OpenOuterVolumeFunctor : public Functor
				{
					OpenOuterVolumeFunctor (const DirectoryPath &outerVolumeMountPoint) : OuterVolumeMountPoint (outerVolumeMountPoint) { }
					
					virtual void operator() ()
					{
						Gui->OpenExplorerWindow (OuterVolumeMountPoint);
					}
					
					DirectoryPath OuterVolumeMountPoint;
				};

				InfoWizardPage *page = new InfoWizardPage (GetPageParent(), _("Open Outer Volume"),
					shared_ptr <Functor> (new OpenOuterVolumeFunctor (MountedOuterVolume->MountPoint)));

				page->SetPageTitle (LangString["HIDVOL_HOST_FILLING_TITLE"]);
				
				page->SetPageText (StringFormatter (
					_("Outer volume has been successfully created and mounted as '{0}'. To this volume you should now copy some sensitive-looking files that you actually do NOT want to hide. The files will be there for anyone forcing you to disclose your password. You will reveal only the password for this outer volume, not for the hidden one. The files that you really care about will be stored in the hidden volume, which will be created later on. When you finish copying, click Next. Do not dismount the volume.\n\nNote: After you click Next, the outer volume will be analyzed to determine the size of uninterrupted area of free space whose end is aligned with the end of the volume. This area will accommodate the hidden volume, so it will limit its maximum possible size. The procedure ensures no data on the outer volume are overwritten by the hidden volume."),
					wstring (MountedOuterVolume->MountPoint)));
				
				return page;
			}

		case Step::HiddenVolume:
			{
				ClearHistory();
				OuterVolume = false;
				LargeFilesSupport = false;

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
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&event), sizeof (event)));
			
			long coord = event.GetX();
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&coord), sizeof (coord)));
			coord = event.GetY();
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&coord), sizeof (coord)));
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
		page->SetProgressValue (progress.SizeDone);

		if (!progress.CreationInProgress && !AbortConfirmationPending)
		{
			SetWorkInProgress (false);
			OnVolumeCreatorFinished ();
		}
	}
	
	void VolumeCreationWizard::OnRandomPoolUpdateTimer ()
	{	
		if (!IsWorkInProgress())
		{
			wxLongLong time = wxGetLocalTimeMillis();
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&time), sizeof (time)));
		}
	}

	void VolumeCreationWizard::OnVolumeCreatorFinished ()
	{
		VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());

		ProgressTimer.reset();
		page->SetProgressState (false);

		Gui->EndInteractiveBusyState (this);
		SetWorkInProgress (false);
		UpdateControls();

		try
		{
			if (!CreationAborted)
			{
				Creator->CheckResult();

#ifdef TC_UNIX
				// Format non-FAT filesystem
				const char *fsFormatter = nullptr;

				switch (SelectedFilesystemType)
				{
				case VolumeCreationOptions::FilesystemType::Ext2:		fsFormatter = "mkfs.ext2"; break;
				case VolumeCreationOptions::FilesystemType::Ext3:		fsFormatter = "mkfs.ext3"; break;
				case VolumeCreationOptions::FilesystemType::Ext4:		fsFormatter = "mkfs.ext4"; break;
				case VolumeCreationOptions::FilesystemType::MacOsExt:	fsFormatter = "newfs_hfs"; break;
				case VolumeCreationOptions::FilesystemType::UFS:		fsFormatter = "newfs" ; break;
				default: break;
				}

				if (fsFormatter)
				{
					wxBusyCursor busy;

					MountOptions mountOptions (Gui->GetPreferences().DefaultMountOptions);
					mountOptions.Path = make_shared <VolumePath> (SelectedVolumePath);
					mountOptions.NoFilesystem = true;
					mountOptions.Protection = VolumeProtection::None;
					mountOptions.Password = Password;
					mountOptions.Keyfiles = Keyfiles;

					shared_ptr <VolumeInfo> volume = Core->MountVolume (mountOptions);
					finally_do_arg (shared_ptr <VolumeInfo>, volume, { Core->DismountVolume (finally_arg, true); });

					Thread::Sleep (2000);	// Try to prevent race conditions caused by OS

					// Temporarily take ownership of the device if the user is not an administrator
					UserId origDeviceOwner ((uid_t) -1);

					DevicePath virtualDevice = volume->VirtualDevice;
#ifdef TC_MACOSX
					string virtualDeviceStr = virtualDevice;
					if (virtualDeviceStr.find ("/dev/rdisk") != 0)
						virtualDevice = "/dev/r" + virtualDeviceStr.substr (5);
#endif
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

					// Create filesystem
					list <string> args;

					if (SelectedFilesystemType == VolumeCreationOptions::FilesystemType::MacOsExt && VolumeSize >= 10 * BYTES_PER_MB)
						args.push_back ("-J");

					args.push_back (string (virtualDevice));

					Process::Execute (fsFormatter, args);
				}
#endif // TC_UNIX

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
			Gui->ShowError (e);
		}

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
						Gui->ShowInfo ("DISMOUNT_FIRST");
						return GetCurrentStep();
					}

					if (SelectedVolumePath.IsDevice())
					{
						if (!DeviceWarningConfirmed && !Gui->AskYesNo (LangString["FORMAT_DEVICE_FOR_ADVANCED_ONLY"]))
							return GetCurrentStep();

						DeviceWarningConfirmed = true;

						foreach_ref (const HostDevice &drive, Core->GetHostDevices())
						{
							if (drive.Path == SelectedVolumePath && !drive.Partitions.empty())
							{
								foreach_ref (const HostDevice &partition, drive.Partitions)
								{
									if (partition.MountPoint == "/")
									{
										Gui->ShowError (_("Error: You are trying to encrypt a system drive.\n\nVeraCrypt can encrypt a system drive only under Windows."));
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
									Gui->ShowError (_("Error: You are trying to encrypt a system partition.\n\nVeraCrypt can encrypt system partitions only under Windows."));
									return GetCurrentStep();
								}

								if (!Gui->AskYesNo (StringFormatter (_("WARNING: Formatting of the device will destroy all data on filesystem '{0}'.\n\nDo you want to continue?"), wstring (mountPoint)), false, true))
									return GetCurrentStep();

								try
								{
									Core->DismountFilesystem (mountPoint, true);
								}
								catch (exception &e)
								{
									Gui->ShowError (e);
									Gui->ShowError (StringFormatter (_("The filesystem of the selected device is currently mounted. Please dismount '{0}' before proceeding."), wstring (mountPoint)));
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
				SelectedHash = page->GetHash ();

				if (forward)
					RandomNumberGenerator::SetHash (SelectedHash);

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
				Password = page->GetPassword();
				Keyfiles = page->GetKeyfiles();

				if (forward && Password && !Password->IsEmpty())
				{
					try
					{
						Password->CheckPortability();
					}
					catch (UnportablePassword &e)
					{
						Gui->ShowError (e);
						return GetCurrentStep();
					}

					if (Password->Size() < VolumePassword::WarningSizeThreshold
						&& !Gui->AskYesNo (LangString["PASSWORD_LENGTH_WARNING"], false, true))
					{
						return GetCurrentStep();
					}
				}

				if (forward && OuterVolume)
				{
					// Use FAT to prevent problems with free space
					QuickFormatEnabled = false;
					SelectedFilesystemType = VolumeCreationOptions::FilesystemType::FAT;
					return Step::CreationProgress;
				}

				if (VolumeSize > 4 * BYTES_PER_GB)
				{
					if (VolumeSize <= TC_MAX_FAT_SECTOR_COUNT * SectorSize)
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
				SelectedFilesystemType = page->GetFilesystemType();
				QuickFormatEnabled = page->IsQuickFormatEnabled();

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
					Gui->ShowWarning (StringFormatter (_("Please note that the volume will not be formatted with a FAT filesystem and, therefore, you may be required to install additional filesystem drivers on platforms other than {0}, which will enable you to mount the volume."), SystemInfo::GetPlatformName())); 

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
						if (OuterVolume && VolumeSize > TC_MAX_FAT_SECTOR_COUNT * SectorSize)
						{
							uint64 limit = TC_MAX_FAT_SECTOR_COUNT * SectorSize / BYTES_PER_TB;
							wstring err = StringFormatter (_("Error: The hidden volume to be created is larger than {0} TB ({1} GB).\n\nPossible solutions:\n- Create a container/partition smaller than {0} TB.\n"), limit, limit * 1024);

							if (SectorSize < 4096)
							{
								err += _("- Use a drive with 4096-byte sectors to be able to create partition/device-hosted hidden volumes up to 16 TB in size");
#if defined (TC_LINUX)
								err += _(".\n");
#else
								err += _(" (not supported by components available on this platform).\n");
#endif
							}

							Gui->ShowError (err);
							return GetCurrentStep();
						}

						if (SelectedVolumePath.IsDevice())
						{
							wxString confirmMsg = LangString["OVERWRITEPROMPT_DEVICE"];
							confirmMsg.Replace (L"%hs", L"%s");

							if (!Gui->AskYesNo (wxString::Format (confirmMsg, wxString (_("DEVICE")).c_str(), wstring (SelectedVolumePath).c_str(), L""), false, true))
								return GetCurrentStep();
						}
						else if (FilesystemPath (wstring (SelectedVolumePath)).IsFile())
						{
							wxString confirmMsg = LangString["OVERWRITEPROMPT"];
							confirmMsg.Replace (L"%hs", L"%s");

							if (!Gui->AskYesNo (wxString::Format (confirmMsg, wstring (SelectedVolumePath).c_str(), false, true)))
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
						options->Keyfiles = Keyfiles;
						options->Path = SelectedVolumePath;
						options->Quick = QuickFormatEnabled;
						options->Size = VolumeSize;
						options->Type = OuterVolume ? VolumeType::Normal : SelectedVolumeType;
						options->VolumeHeaderKdf = Pkcs5Kdf::GetAlgorithm (*SelectedHash);

						Creator.reset (new VolumeCreator);
						Creator->CreateVolume (options);

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
						Gui->ShowError (e);
					}
				}

				return GetCurrentStep();
			}

		case Step::VolumeCreatedInfo:
			Creator.reset();
			SetCancelButtonText (L"");

			return Step::VolumeHostType;

		case Step::OuterVolumeContents:
			try
			{
				// Determine maximum size of the hidden volume. Scan cluster table offline as a live filesystem test would
				// require using FUSE and loop device which cannot be used for devices with sectors larger than 512.

				wxBusyCursor busy;
				MaxHiddenVolumeSize = 0;

				Gui->SetActiveFrame (this);

				if (MountedOuterVolume)
				{
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

				shared_ptr <Volume> outerVolume = Core->OpenVolume (make_shared <VolumePath> (SelectedVolumePath), true, Password, Keyfiles, VolumeProtection::ReadOnly);
				MaxHiddenVolumeSize = Core->GetMaxHiddenVolumeSize (outerVolume);

				// Add a reserve (in case the user mounts the outer volume and creates new files
				// on it by accident or OS writes some new data behind his or her back, such as
				// System Restore etc.)

				uint64 reservedSize = outerVolume->GetSize() / 200;
				if (reservedSize > 10 * BYTES_PER_MB)
					reservedSize = 10 * BYTES_PER_MB;
	
				if (MaxHiddenVolumeSize < reservedSize)
					MaxHiddenVolumeSize = 0;
				else
					MaxHiddenVolumeSize -= reservedSize;

				MaxHiddenVolumeSize -= MaxHiddenVolumeSize % outerVolume->GetSectorSize();		// Must be a multiple of the sector size
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
