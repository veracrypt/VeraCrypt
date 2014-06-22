/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
		auto_ptr <VolumeCreator> Creator;
		bool CrossPlatformSupport;
		static bool DeviceWarningConfirmed;
		bool DisplayKeyInfo;
		auto_ptr <wxTimer> ProgressTimer;
		auto_ptr <wxTimer> RandomPoolUpdateTimer;
		shared_ptr <KeyfileList> Keyfiles;
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
		uint32 SectorSize;
		shared_ptr <Hash> SelectedHash;
		uint64 VolumeSize;

	private:
		void UpdateControls ();
	};
}

#endif // TC_HEADER_Main_Forms_VolumeCreationWizard
