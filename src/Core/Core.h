/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Core_Core
#define TC_HEADER_Core_Core

#include "CoreBase.h"

namespace VeraCrypt
{
	extern unique_ptr <CoreBase> Core;
	extern unique_ptr <CoreBase> CoreDirect;

	class WaitThreadRoutine
	{
	public:
		Exception* m_pException;
		WaitThreadRoutine() : m_pException(NULL) {}
		virtual ~WaitThreadRoutine() {if (m_pException) delete m_pException;}
		bool HasException () { return m_pException != NULL;}
		Exception* GetException () const { return m_pException;}
		void Execute(void)
		{
			try
			{
				ExecutionCode();
			}
			catch(Exception& ex)
			{
				m_pException = ex.CloneNew();
			}
			catch(...)
			{
				m_pException = new UnknownException (SRC_POS);
			}
		}
		virtual void ExecutionCode(void) = 0;
	};

	class MountThreadRoutine : public WaitThreadRoutine
	{
	public:
		MountOptions& m_options;
		shared_ptr <VolumeInfo> m_pVolume;
		MountThreadRoutine(MountOptions &options) : m_options(options) {}
		virtual ~MountThreadRoutine() { }
		virtual void ExecutionCode(void) { m_pVolume = Core->MountVolume(m_options); }
	};

	class VolumeCreatorThreadRoutine : public WaitThreadRoutine
	{
	public:
		shared_ptr <VolumeCreationOptions> m_options;
		shared_ptr <VolumeCreator> m_pCreator;
		VolumeCreatorThreadRoutine(shared_ptr <VolumeCreationOptions> options, shared_ptr <VolumeCreator> pCreator)
			: m_options(options), m_pCreator(pCreator) {}
		virtual ~VolumeCreatorThreadRoutine() { }
		virtual void ExecutionCode(void) { m_pCreator->CreateVolume (m_options); }
	};

	class ChangePasswordThreadRoutine : public WaitThreadRoutine
	{
	public:
		shared_ptr <VolumePath> m_volumePath;
		bool m_preserveTimestamps;
		shared_ptr <VolumePassword> m_password;
		int m_pim;
		shared_ptr <Pkcs5Kdf> m_kdf;
		shared_ptr <KeyfileList> m_keyfiles;
		shared_ptr <VolumePassword> m_newPassword;
		int m_newPim;
		shared_ptr <KeyfileList> m_newKeyfiles;
		shared_ptr <Pkcs5Kdf> m_newPkcs5Kdf;
		int m_wipeCount;
		bool m_emvSupportEnabled;
		bool m_masterKeyVulnerable;
		ChangePasswordThreadRoutine(shared_ptr <VolumePath> volumePath, bool preserveTimestamps, shared_ptr <VolumePassword> password, int pim, shared_ptr <Pkcs5Kdf> kdf, shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> newPassword, int newPim, shared_ptr <KeyfileList> newKeyfiles, shared_ptr <Pkcs5Kdf> newPkcs5Kdf, int wipeCount, bool emvSupportEnabled) : m_volumePath(volumePath), m_preserveTimestamps(preserveTimestamps), m_password(password), m_pim(pim), m_kdf(kdf), m_keyfiles(keyfiles), m_newPassword(newPassword), m_newPim(newPim), m_newKeyfiles(newKeyfiles), m_newPkcs5Kdf(newPkcs5Kdf), m_wipeCount(wipeCount), m_emvSupportEnabled(emvSupportEnabled), m_masterKeyVulnerable(false)  {}
		virtual ~ChangePasswordThreadRoutine() { }
		virtual void ExecutionCode(void) { 
			shared_ptr <Volume> openVolume = Core->ChangePassword(m_volumePath, m_preserveTimestamps, m_password, m_pim, m_kdf, m_keyfiles, m_newPassword, m_newPim, m_newKeyfiles, m_emvSupportEnabled, m_newPkcs5Kdf, m_wipeCount); 
			m_masterKeyVulnerable = openVolume->IsMasterKeyVulnerable();
		}
	};

	class OpenVolumeThreadRoutine : public WaitThreadRoutine
	{
	public:
		shared_ptr <VolumePath> m_volumePath;
		bool m_preserveTimestamps;
		shared_ptr <VolumePassword> m_password;
		int m_pim;
		shared_ptr<Pkcs5Kdf> m_Kdf;
		shared_ptr <KeyfileList> m_keyfiles;
		VolumeProtection::Enum m_protection;
		shared_ptr <VolumePassword> m_protectionPassword;
		int m_protectionPim;
		shared_ptr<Pkcs5Kdf> m_protectionKdf;
		shared_ptr <KeyfileList> m_protectionKeyfiles;
		bool m_sharedAccessAllowed;
		VolumeType::Enum m_volumeType;
		bool m_useBackupHeaders;
		bool m_partitionInSystemEncryptionScope;
		shared_ptr <Volume> m_pVolume;
		bool m_emvSupportEnabled;

		OpenVolumeThreadRoutine(shared_ptr <VolumePath> volumePath, bool preserveTimestamps, shared_ptr <VolumePassword> password, int pim, shared_ptr<Pkcs5Kdf> Kdf, shared_ptr <KeyfileList> keyfiles, bool emvSupportEnabled, VolumeProtection::Enum protection = VolumeProtection::None, shared_ptr <VolumePassword> protectionPassword = shared_ptr <VolumePassword> (), int protectionPim = 0, shared_ptr<Pkcs5Kdf> protectionKdf = shared_ptr<Pkcs5Kdf> (), shared_ptr <KeyfileList> protectionKeyfiles = shared_ptr <KeyfileList> (), bool sharedAccessAllowed = false, VolumeType::Enum volumeType = VolumeType::Unknown, bool useBackupHeaders = false, bool partitionInSystemEncryptionScope = false):
		m_volumePath(volumePath), m_preserveTimestamps(preserveTimestamps), m_password(password), m_pim(pim), m_Kdf(Kdf), m_keyfiles(keyfiles),
		m_protection(protection), m_protectionPassword(protectionPassword), m_protectionPim(protectionPim), m_protectionKdf(protectionKdf), m_protectionKeyfiles(protectionKeyfiles), m_sharedAccessAllowed(sharedAccessAllowed), m_volumeType(volumeType),m_useBackupHeaders(useBackupHeaders),
		m_partitionInSystemEncryptionScope(partitionInSystemEncryptionScope), m_emvSupportEnabled(emvSupportEnabled) {}

		~OpenVolumeThreadRoutine() {}

		virtual void ExecutionCode(void) { m_pVolume = Core->OpenVolume(m_volumePath,m_preserveTimestamps,m_password,m_pim,m_Kdf,m_keyfiles, m_emvSupportEnabled, m_protection,m_protectionPassword,m_protectionPim,m_protectionKdf, m_protectionKeyfiles,m_sharedAccessAllowed,m_volumeType,m_useBackupHeaders, m_partitionInSystemEncryptionScope); }

	};

	class ReEncryptHeaderThreadRoutine : public WaitThreadRoutine
	{
	public:
		const BufferPtr &m_newHeaderBuffer;
		shared_ptr <VolumeHeader> m_header;
		shared_ptr <VolumePassword> m_password;
		int m_pim;
		shared_ptr <KeyfileList> m_keyfiles;
		bool m_emvSupportEnabled;
		ReEncryptHeaderThreadRoutine(const BufferPtr &newHeaderBuffer, shared_ptr <VolumeHeader> header, shared_ptr <VolumePassword> password, int pim, shared_ptr <KeyfileList> keyfiles, bool emvSupportEnabled)
			: m_newHeaderBuffer(newHeaderBuffer), m_header(header), m_password(password), m_pim(pim), m_keyfiles(keyfiles), m_emvSupportEnabled(emvSupportEnabled) {}
		virtual ~ReEncryptHeaderThreadRoutine() { }
		virtual void ExecutionCode(void) { Core->ReEncryptVolumeHeaderWithNewSalt (m_newHeaderBuffer, m_header, m_password, m_pim, m_keyfiles, m_emvSupportEnabled); }
	};

	class DecryptThreadRoutine : public WaitThreadRoutine
	{
	public:
		shared_ptr <VolumeHeader> m_pHeader;
		const ConstBufferPtr &m_encryptedData;
		const VolumePassword &m_password;
		int m_pim;
		shared_ptr <Pkcs5Kdf> m_kdf;
		const Pkcs5KdfList &m_keyDerivationFunctions;
		const EncryptionAlgorithmList &m_encryptionAlgorithms;
		const EncryptionModeList &m_encryptionModes;
		bool m_bResult;
		DecryptThreadRoutine(shared_ptr <VolumeHeader> header, const ConstBufferPtr &encryptedData, const VolumePassword &password, int pim, shared_ptr <Pkcs5Kdf> kdf, const Pkcs5KdfList &keyDerivationFunctions, const EncryptionAlgorithmList &encryptionAlgorithms, const EncryptionModeList &encryptionModes)
			: m_pHeader(header), m_encryptedData(encryptedData), m_password(password), m_pim(pim), m_kdf(kdf), m_keyDerivationFunctions(keyDerivationFunctions), m_encryptionAlgorithms(encryptionAlgorithms), m_encryptionModes(encryptionModes), m_bResult(false){}
		virtual ~DecryptThreadRoutine() { }
		virtual void ExecutionCode(void) { m_bResult = m_pHeader->Decrypt(m_encryptedData, m_password, m_pim, m_kdf, m_keyDerivationFunctions, m_encryptionAlgorithms, m_encryptionModes); }
	};

	class WaitThreadUI
	{
	public:
		WaitThreadUI(WaitThreadRoutine* pRoutine): m_pRoutine(pRoutine) {}
		virtual ~WaitThreadUI() {}
		virtual void Run(void) { m_pRoutine->ExecutionCode();}
		WaitThreadRoutine* m_pRoutine;
	};
}

#endif // TC_HEADER_Core_Core
