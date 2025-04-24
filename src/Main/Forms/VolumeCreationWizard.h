/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_VolumeCreationWizard
#define TC_HEADER_Main_Forms_VolumeCreationWizard

#include "WizardFrame.h"
#include "Core/VolumeCreator.h"

namespace VeraCrypt
{
	class VolumeCreationWizard : public WizardFrame
	{
	public:
		VolumeCreationWizard (wxWindow* parent);
		~VolumeCreationWizard ();

#ifdef TC_MACOSX
		virtual bool ProcessEvent(wxEvent& event);
#endif

	protected:
		struct Step
		{
			enum Enum
			{
				VolumeHostType,
				VolumeType,
				VolumeLocation,
				EncryptionOptions,
				VolumeSize,
				VolumePassword,
				VolumePim,
				LargeFilesSupport,
				FormatOptions,
				CrossPlatformSupport,
				CreationProgress,
				VolumeCreatedInfo,
				OuterVolumeContents,
				HiddenVolume
			};
		};

		void CreateVolume ();
		WizardPage *GetPage (WizardStep step);
		void OnAbortButtonClick (EventArgs &args);
		void OnMouseMotion (wxMouseEvent& event);
		void OnProgressTimer ();
		void OnRandomPoolUpdateTimer ();
		void OnThreadExiting (wxCommandEvent& event);
		void OnVolumeCreatorFinished ();
		WizardStep ProcessPageChangeRequest (bool forward);

		volatile bool AbortConfirmationPending;
		volatile bool AbortRequested;
		volatile bool CreationAborted;
		shared_ptr <VolumeCreator> Creator;
		bool CrossPlatformSupport;
		static bool DeviceWarningConfirmed;
		bool DisplayKeyInfo;
		unique_ptr <wxTimer> ProgressTimer;
		unique_ptr <wxTimer> RandomPoolUpdateTimer;
		shared_ptr <KeyfileList> Keyfiles;
		wstring SecurityTokenSchemeSpec;
		bool LargeFilesSupport;
		uint64 MaxHiddenVolumeSize;
		shared_ptr <VolumeInfo> MountedOuterVolume;
		bool OuterVolume;
		bool QuickFormatEnabled;
		shared_ptr <EncryptionAlgorithm> SelectedEncryptionAlgorithm;
		uint32 SelectedFilesystemClusterSize;
		VolumeCreationOptions::FilesystemType::Enum SelectedFilesystemType;
		VolumePath SelectedVolumePath;
		VolumeHostType::Enum SelectedVolumeHostType;
		VolumeType::Enum SelectedVolumeType;
		shared_ptr <VolumePassword> Password;
		shared_ptr <VolumePassword> OuterPassword;
		int Pim;
		int OuterPim;
		shared_ptr <Pkcs5Kdf> Kdf;
		uint32 SectorSize;
		shared_ptr <Hash> SelectedHash;
		uint64 VolumeSize;

	private:
		void UpdateControls ();
	};
}

#endif // TC_HEADER_Main_Forms_VolumeCreationWizard
