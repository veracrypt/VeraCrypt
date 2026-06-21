/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Crc32.h"
#include "EncryptionThreadPool.h"
#include "EncryptionModeXTS.h"
#ifdef WOLFCRYPT_BACKEND
#include "EncryptionModeWolfCryptXTS.h"
#endif
#include "Pkcs5Kdf.h"
#include "VolumeHeader.h"
#include "VolumeException.h"
#include "Common/Crypto.h"

namespace VeraCrypt
{
	static void DrainKeyDerivationWorkItems (SyncEvent &noOutstandingWorkItemEvent, size_t enqueuedWorkItemCount, bool &workItemsDrained)
	{
		if (enqueuedWorkItemCount > 0 && !workItemsDrained)
		{
			noOutstandingWorkItemEvent.Wait();
			workItemsDrained = true;
		}
	}

	VolumeHeader::VolumeHeader (uint32 size)
	{
		Init();
		HeaderSize = size;
		EncryptedHeaderDataSize = size - EncryptedHeaderDataOffset;
	}

	VolumeHeader::~VolumeHeader ()
	{
		Init();
	}

	void VolumeHeader::Init ()
	{
		VolumeKeyAreaCrc32 = 0;
		VolumeCreationTime = 0;
		HeaderCreationTime = 0;
		mVolumeType = VolumeType::Unknown;
		HiddenVolumeDataSize = 0;
		VolumeDataSize = 0;
		EncryptedAreaStart = 0;
		EncryptedAreaLength = 0;
		Flags = 0;
		SectorSize = 0;
		XtsKeyVulnerable = false;
	}

	void VolumeHeader::Create (const BufferPtr &headerBuffer, VolumeHeaderCreationOptions &options)
	{
		if (options.DataKey.Size() != options.EA->GetKeySize() * 2 || options.Salt.Size() != GetSaltSize())
			throw ParameterIncorrect (SRC_POS);

		headerBuffer.Zero();

		HeaderVersion = CurrentHeaderVersion;
		RequiredMinProgramVersion = CurrentRequiredMinProgramVersion;

		DataAreaKey.Zero();
		DataAreaKey.CopyFrom (options.DataKey);

		// check if the XTS key is vulnerable by comparing the two parts of the key
		XtsKeyVulnerable = (memcmp (options.DataKey.Get() + options.EA->GetKeySize(), options.DataKey.Get(), options.EA->GetKeySize()) == 0);

		VolumeCreationTime = 0;
		HiddenVolumeDataSize = (options.Type == VolumeType::Hidden ? options.VolumeDataSize : 0);
		VolumeDataSize = options.VolumeDataSize;

		EncryptedAreaStart = options.VolumeDataStart;
		EncryptedAreaLength = options.VolumeDataSize;

		SectorSize = options.SectorSize;

		if (SectorSize < TC_MIN_VOLUME_SECTOR_SIZE
			|| SectorSize > TC_MAX_VOLUME_SECTOR_SIZE
			|| SectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
		{
			throw ParameterIncorrect (SRC_POS);
		}

		EA = options.EA;
            #ifdef WOLFCRYPT_BACKEND
                shared_ptr <EncryptionMode> mode (new EncryptionModeWolfCryptXTS ());
            #else
                shared_ptr <EncryptionMode> mode (new EncryptionModeXTS ());
            #endif
                EA->SetMode (mode);

		EncryptNew (headerBuffer, options.Salt, options.HeaderKey, options.Kdf);
	}

	bool VolumeHeader::Decrypt (const ConstBufferPtr &encryptedData, const VolumePassword &password, int pim, shared_ptr <Pkcs5Kdf> kdf, const Pkcs5KdfList &keyDerivationFunctions, const EncryptionAlgorithmList &encryptionAlgorithms, const EncryptionModeList &encryptionModes)
	{
		if (password.Size() < 1)
			throw PasswordEmpty (SRC_POS);

		ConstBufferPtr salt (encryptedData.GetRange (SaltOffset, SaltSize));

		if (!kdf && EncryptionThreadPool::IsRunning() && keyDerivationFunctions.size() > 1)
		{
			typedef EncryptionThreadPool::KeyDerivationWorkItem KeyDerivationWorkItem;

			list < shared_ptr <KeyDerivationWorkItem> > keyDerivationWorkItems;
			SharedVal <size_t> outstandingWorkItemCount (0);
			SyncEvent keyDerivationCompletedEvent;
			SyncEvent noOutstandingWorkItemEvent;
			long volatile abortKeyDerivation = 0;
			size_t enqueuedWorkItemCount = 0;
			size_t processedWorkItemCount = 0;
			bool workItemsDrained = false;

			try
			{
				foreach (shared_ptr <Pkcs5Kdf> pkcs5, keyDerivationFunctions)
				{
					shared_ptr <KeyDerivationWorkItem> keyDerivationWorkItem (new KeyDerivationWorkItem (pkcs5, GetHeaderKeyDerivationSize (pkcs5)));
					keyDerivationWorkItems.push_back (keyDerivationWorkItem);
					EncryptionThreadPool::BeginKeyDerivation (*keyDerivationWorkItem, password, pim, salt, keyDerivationCompletedEvent, noOutstandingWorkItemEvent, outstandingWorkItemCount, &abortKeyDerivation);
					++enqueuedWorkItemCount;
				}

				while (processedWorkItemCount < keyDerivationWorkItems.size())
				{
					bool processed = false;

					foreach (shared_ptr <KeyDerivationWorkItem> keyDerivationWorkItem, keyDerivationWorkItems)
					{
						if (!keyDerivationWorkItem->Processed && keyDerivationWorkItem->Completed.Get())
						{
							keyDerivationWorkItem->Processed = true;
							++processedWorkItemCount;
							processed = true;

							if (keyDerivationWorkItem->ItemException.get())
							{
								// KDF exceptions are fatal setup/runtime errors; candidate failures are reported via Result.
								abortKeyDerivation = 1;
								DrainKeyDerivationWorkItems (noOutstandingWorkItemEvent, enqueuedWorkItemCount, workItemsDrained);
								keyDerivationWorkItem->ItemException->Throw();
							}

							if (keyDerivationWorkItem->Result != 0)
								continue;

							if (DecryptWithHeaderKey (encryptedData, keyDerivationWorkItem->Kdf, keyDerivationWorkItem->DerivedKey, encryptionAlgorithms, encryptionModes))
							{
								abortKeyDerivation = 1;
								DrainKeyDerivationWorkItems (noOutstandingWorkItemEvent, enqueuedWorkItemCount, workItemsDrained);
								return true;
							}
						}
					}

					if (processedWorkItemCount < keyDerivationWorkItems.size() && !processed)
						keyDerivationCompletedEvent.Wait();
				}
			}
			catch (...)
			{
				abortKeyDerivation = 1;
				DrainKeyDerivationWorkItems (noOutstandingWorkItemEvent, enqueuedWorkItemCount, workItemsDrained);
				throw;
			}

			DrainKeyDerivationWorkItems (noOutstandingWorkItemEvent, enqueuedWorkItemCount, workItemsDrained);
			return false;
		}

		foreach (shared_ptr <Pkcs5Kdf> pkcs5, keyDerivationFunctions)
		{
			if (kdf && (kdf->GetName() != pkcs5->GetName()))
				continue;

			SecureBuffer headerKey (GetHeaderKeyDerivationSize (pkcs5));
			int derivationResult = pkcs5->DeriveKey (headerKey, password, pim, salt);
			if (derivationResult != 0)
			{
				if (!kdf)
					continue;

				throw ExternalException (SRC_POS, pkcs5->GetDerivationFailureMessage (derivationResult));
			}

			if (DecryptWithHeaderKey (encryptedData, pkcs5, headerKey, encryptionAlgorithms, encryptionModes))
				return true;
		}

		return false;
	}

	int VolumeHeader::DecryptHeaderParallel (const vector <DecryptCandidate> &candidates, const VolumePassword &password, int pim)
	{
		if (password.Size() < 1)
			throw PasswordEmpty (SRC_POS);

		if (!EncryptionThreadPool::IsRunning())
			return -1;

		typedef EncryptionThreadPool::KeyDerivationWorkItem KeyDerivationWorkItem;

		// One work item per (candidate x KDF). 'Tested' guards DecryptWithHeaderKey
		// against being re-run on the same item across resolution passes.
		struct Entry
		{
			shared_ptr <KeyDerivationWorkItem> Item;
			bool Tested;
		};

		// Grouped by candidate so candidates can be resolved in their original
		// (priority) order even though the derivations complete concurrently.
		vector < vector <Entry> > candidateEntries (candidates.size());
		SharedVal <size_t> outstandingWorkItemCount (0);
		SyncEvent keyDerivationCompletedEvent;
		SyncEvent noOutstandingWorkItemEvent;
		long volatile abortKeyDerivation = 0;
		size_t enqueuedWorkItemCount = 0;
		bool workItemsDrained = false;

		try
		{
			for (size_t ci = 0; ci < candidates.size(); ++ci)
			{
				const DecryptCandidate &candidate = candidates[ci];
				// The salt is a view into the candidate's header buffer, which the
				// caller keeps alive for the duration of this call.
				ConstBufferPtr salt (candidate.EncryptedData.GetRange (SaltOffset, SaltSize));

				foreach (shared_ptr <Pkcs5Kdf> pkcs5, candidate.KeyDerivationFunctions)
				{
					Entry entry;
					entry.Item = shared_ptr <KeyDerivationWorkItem> (new KeyDerivationWorkItem (pkcs5, GetHeaderKeyDerivationSize (pkcs5)));
					entry.Tested = false;
					candidateEntries[ci].push_back (entry);

					EncryptionThreadPool::BeginKeyDerivation (*entry.Item, password, pim, salt, keyDerivationCompletedEvent, noOutstandingWorkItemEvent, outstandingWorkItemCount, &abortKeyDerivation);
					++enqueuedWorkItemCount;
				}
			}

			// Resolve candidates strictly in priority order, preserving the serial
			// detection semantics: candidate N is only considered once every
			// higher-priority candidate is known not to decrypt (and not to throw).
			// Within a candidate, the first KDF whose derived key decrypts the header
			// wins, so a fast match does not wait on that candidate's slow KDFs.
			size_t nextCandidate = 0;
			while (nextCandidate < candidates.size())
			{
				bool recordedCompletion = false;

				// Mark newly completed work items as done across all remaining
				// candidates so the completion signal is fully consumed each pass.
				for (size_t ci = nextCandidate; ci < candidates.size(); ++ci)
				{
					for (size_t i = 0; i < candidateEntries[ci].size(); ++i)
					{
						Entry &entry = candidateEntries[ci][i];
						if (!entry.Item->Processed && entry.Item->Completed.Get())
						{
							entry.Item->Processed = true;
							recordedCompletion = true;
						}
					}
				}

				// Try to resolve the current (highest remaining priority) candidate.
				const DecryptCandidate &candidate = candidates[nextCandidate];
				vector <Entry> &entries = candidateEntries[nextCandidate];
				bool candidateComplete = true;

				for (size_t i = 0; i < entries.size(); ++i)
				{
					Entry &entry = entries[i];
					if (!entry.Item->Processed)
					{
						candidateComplete = false;
						continue;
					}

					if (entry.Item->ItemException.get())
					{
						// KDF exceptions are fatal; surfaced in candidate priority order.
						abortKeyDerivation = 1;
						DrainKeyDerivationWorkItems (noOutstandingWorkItemEvent, enqueuedWorkItemCount, workItemsDrained);
						entry.Item->ItemException->Throw();
					}

					if (entry.Tested)
						continue;

					entry.Tested = true;

					if (entry.Item->Result != 0)
						continue;

					// DecryptWithHeaderKey may throw (e.g. HigherVersionRequired); it
					// runs only for the highest-priority unresolved candidate, so that
					// exception keeps the same priority as the serial path.
					if (candidate.Header->DecryptWithHeaderKey (candidate.EncryptedData, entry.Item->Kdf, entry.Item->DerivedKey, candidate.EncryptionAlgorithms, candidate.EncryptionModes))
					{
						abortKeyDerivation = 1;
						DrainKeyDerivationWorkItems (noOutstandingWorkItemEvent, enqueuedWorkItemCount, workItemsDrained);
						return (int) nextCandidate;
					}
				}

				if (candidateComplete)
				{
					// All of this candidate's KDFs finished without a match.
					++nextCandidate;
					continue;
				}

				// Current candidate still has outstanding derivations; if nothing new
				// was recorded this pass, block until another work item completes.
				if (!recordedCompletion)
					keyDerivationCompletedEvent.Wait();
			}
		}
		catch (...)
		{
			abortKeyDerivation = 1;
			DrainKeyDerivationWorkItems (noOutstandingWorkItemEvent, enqueuedWorkItemCount, workItemsDrained);
			throw;
		}

		DrainKeyDerivationWorkItems (noOutstandingWorkItemEvent, enqueuedWorkItemCount, workItemsDrained);
		return -1;
	}

	bool VolumeHeader::DecryptWithHeaderKey (const ConstBufferPtr &encryptedData, shared_ptr <Pkcs5Kdf> pkcs5, const ConstBufferPtr &headerKey, const EncryptionAlgorithmList &encryptionAlgorithms, const EncryptionModeList &encryptionModes)
	{
		SecureBuffer header (EncryptedHeaderDataSize);

		foreach (shared_ptr <EncryptionMode> mode, encryptionModes)
		{
			#ifdef WOLFCRYPT_BACKEND
			bool xtsMode = typeid (*mode) == typeid (EncryptionModeWolfCryptXTS);
			#else
			bool xtsMode = typeid (*mode) == typeid (EncryptionModeXTS);
			#endif

			if (!xtsMode)
			{
				if (mode->GetKeySize() > headerKey.Size())
					continue;
				mode->SetKey (headerKey.GetRange (0, mode->GetKeySize()));
			}

			foreach (shared_ptr <EncryptionAlgorithm> ea, encryptionAlgorithms)
			{
				if (!ea->IsModeSupported (mode))
					continue;

				size_t requiredHeaderKeySize = xtsMode ? ea->GetKeySize() * 2 : LegacyEncryptionModeKeyAreaSize + ea->GetKeySize();
				if (requiredHeaderKeySize > headerKey.Size())
					continue;

				if (xtsMode)
				{
					ea->SetKey (headerKey.GetRange (0, ea->GetKeySize()));
				#ifdef WOLFCRYPT_BACKEND
					ea->SetKeyXTS (headerKey.GetRange (ea->GetKeySize(), ea->GetKeySize()));
				#endif

					mode = mode->GetNew();
					mode->SetKey (headerKey.GetRange (ea->GetKeySize(), ea->GetKeySize()));
				}
				else
				{
					ea->SetKey (headerKey.GetRange (LegacyEncryptionModeKeyAreaSize, ea->GetKeySize()));
				}

				ea->SetMode (mode);

				header.CopyFrom (encryptedData.GetRange (EncryptedHeaderDataOffset, EncryptedHeaderDataSize));
				ea->Decrypt (header);

				if (Deserialize (header, ea, mode))
				{
					EA = ea;
					Pkcs5 = pkcs5;
					return true;
				}
			}
		}

		return false;
	}

	bool VolumeHeader::Deserialize (const ConstBufferPtr &header, shared_ptr <EncryptionAlgorithm> &ea, shared_ptr <EncryptionMode> &mode)
	{
		if (header.Size() != EncryptedHeaderDataSize)
			throw ParameterIncorrect (SRC_POS);

		if ((header[0] != 'V' ||
			header[1] != 'E' ||
			header[2] != 'R' ||
			header[3] != 'A'))
			return false;

		size_t offset = 4;
		HeaderVersion =	DeserializeEntry <uint16> (header, offset);

		if (HeaderVersion < MinAllowedHeaderVersion)
			return false;

		if (HeaderVersion > CurrentHeaderVersion)
			throw HigherVersionRequired (SRC_POS);

		if (HeaderVersion >= 4
			&& Crc32::ProcessBuffer (header.GetRange (0, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC))
			!= DeserializeEntryAt <uint32> (header, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC))
		{
			return false;
		}

		RequiredMinProgramVersion = DeserializeEntry <uint16> (header, offset);

		if ((RequiredMinProgramVersion > Version::Number()))
			throw HigherVersionRequired (SRC_POS);

		VolumeKeyAreaCrc32 = DeserializeEntry <uint32> (header, offset);
		VolumeCreationTime = DeserializeEntry <uint64> (header, offset);
		HeaderCreationTime = DeserializeEntry <uint64> (header, offset);
		HiddenVolumeDataSize = DeserializeEntry <uint64> (header, offset);
		mVolumeType = (HiddenVolumeDataSize != 0 ? VolumeType::Hidden : VolumeType::Normal);
		VolumeDataSize = DeserializeEntry <uint64> (header, offset);
		EncryptedAreaStart = DeserializeEntry <uint64> (header, offset);
		EncryptedAreaLength = DeserializeEntry <uint64> (header, offset);
		Flags = DeserializeEntry <uint32> (header, offset);

		SectorSize = DeserializeEntry <uint32> (header, offset);
		if (HeaderVersion < 5)
			SectorSize = TC_SECTOR_SIZE_LEGACY;

		if (SectorSize < TC_MIN_VOLUME_SECTOR_SIZE
			|| SectorSize > TC_MAX_VOLUME_SECTOR_SIZE
			|| SectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
		{
			throw ParameterIncorrect (SRC_POS);
		}

#if !(defined (TC_WINDOWS) || defined (TC_LINUX) || defined (TC_MACOSX))
		if (SectorSize != TC_SECTOR_SIZE_LEGACY)
			throw UnsupportedSectorSize (SRC_POS);
#endif

		offset = DataAreaKeyOffset;

		if (VolumeKeyAreaCrc32 != Crc32::ProcessBuffer (header.GetRange (offset, DataKeyAreaMaxSize)))
			return false;

		DataAreaKey.CopyFrom (header.GetRange (offset, DataKeyAreaMaxSize));

		ea = ea->GetNew();
		mode = mode->GetNew();

            #ifndef WOLFCRYPT_BACKEND
		if (typeid (*mode) == typeid (EncryptionModeXTS))
		{
                    ea->SetKey (header.GetRange (offset, ea->GetKeySize()));
            #else
		if (typeid (*mode) == typeid (EncryptionModeWolfCryptXTS))
		{
                       ea->SetKey (header.GetRange (offset, ea->GetKeySize()));
			ea->SetKeyXTS (header.GetRange (offset + ea->GetKeySize(), ea->GetKeySize()));
            #endif
			mode->SetKey (header.GetRange (offset + ea->GetKeySize(), ea->GetKeySize()));

			// check if the XTS key is vulnerable by comparing the two parts of the key
			XtsKeyVulnerable = (memcmp (DataAreaKey.Ptr() + ea->GetKeySize(), DataAreaKey.Ptr(), ea->GetKeySize()) == 0);
		}
		else
		{
			mode->SetKey (header.GetRange (offset, mode->GetKeySize()));
			ea->SetKey (header.GetRange (offset + LegacyEncryptionModeKeyAreaSize, ea->GetKeySize()));
		}

		ea->SetMode (mode);

		return true;
	}

	template <typename T>
	T VolumeHeader::DeserializeEntry (const ConstBufferPtr &header, size_t &offset) const
	{
		offset += sizeof (T);

		if (offset > header.Size())
			throw ParameterIncorrect (SRC_POS);

		return Endian::Big (*reinterpret_cast<const T *> (header.Get() + offset - sizeof (T)));
	}

	template <typename T>
	T VolumeHeader::DeserializeEntryAt (const ConstBufferPtr &header, const size_t &offset) const
	{
		if (offset > header.Size())
			throw ParameterIncorrect (SRC_POS);

		return Endian::Big (*reinterpret_cast<const T *> (header.Get() + offset));
	}

	void VolumeHeader::EncryptNew (const BufferPtr &newHeaderBuffer, const ConstBufferPtr &newSalt, const ConstBufferPtr &newHeaderKey, shared_ptr <Pkcs5Kdf> newPkcs5Kdf)
	{
		if (newHeaderBuffer.Size() != HeaderSize || newSalt.Size() != SaltSize)
			throw ParameterIncorrect (SRC_POS);

		shared_ptr <EncryptionMode> mode = EA->GetMode()->GetNew();
		shared_ptr <EncryptionAlgorithm> ea = EA->GetNew();

            #ifndef WOLFCRYPT_BACKEND
		if (typeid (*mode) == typeid (EncryptionModeXTS))
		{
                        ea->SetKey (newHeaderKey.GetRange (0, ea->GetKeySize()));
            #else
		if (typeid (*mode) == typeid (EncryptionModeWolfCryptXTS))
		{
                        ea->SetKey (newHeaderKey.GetRange (0, ea->GetKeySize()));
                        ea->SetKeyXTS (newHeaderKey.GetRange (EA->GetKeySize(), EA->GetKeySize()));
            #endif
                        mode->SetKey (newHeaderKey.GetRange (EA->GetKeySize(), EA->GetKeySize()));
		}
		else
		{
			mode->SetKey (newHeaderKey.GetRange (0, mode->GetKeySize()));
			ea->SetKey (newHeaderKey.GetRange (LegacyEncryptionModeKeyAreaSize, ea->GetKeySize()));
		}

		ea->SetMode (mode);

		newHeaderBuffer.CopyFrom (newSalt);

		BufferPtr headerData = newHeaderBuffer.GetRange (EncryptedHeaderDataOffset, EncryptedHeaderDataSize);
		Serialize (headerData);
		ea->Encrypt (headerData);

		if (newPkcs5Kdf)
			Pkcs5 = newPkcs5Kdf;
	}

	size_t VolumeHeader::GetHeaderKeyDerivationSize (shared_ptr <Pkcs5Kdf> kdf)
	{
	#ifndef VC_DCS_DISABLE_ARGON2
		if (kdf && kdf->IsArgon2())
			return ARGON2_HEADER_KEYDATA_SIZE;
	#endif

		return GetLargestSerializedKeySize();
	}

	size_t VolumeHeader::GetLargestSerializedKeySize ()
	{
		size_t largestKey = EncryptionAlgorithm::GetLargestKeySize (EncryptionAlgorithm::GetAvailableAlgorithms());

		// XTS mode requires the same key size as the encryption algorithm.
		// Legacy modes may require larger key than XTS.
		if (LegacyEncryptionModeKeyAreaSize + largestKey > largestKey * 2)
			return LegacyEncryptionModeKeyAreaSize + largestKey;

		return largestKey * 2;
	}

	void VolumeHeader::Serialize (const BufferPtr &header) const
	{
		if (header.Size() != EncryptedHeaderDataSize)
			throw ParameterIncorrect (SRC_POS);

		header.Zero();

		header[0] = 'V';
		header[1] = 'E';
		header[2] = 'R';
		header[3] = 'A';
		size_t offset = 4;

		header.GetRange (DataAreaKeyOffset, DataAreaKey.Size()).CopyFrom (DataAreaKey);

		uint16 headerVersion = CurrentHeaderVersion;
		SerializeEntry (headerVersion, header, offset);
		SerializeEntry (RequiredMinProgramVersion, header, offset);
		SerializeEntry (Crc32::ProcessBuffer (header.GetRange (DataAreaKeyOffset, DataKeyAreaMaxSize)), header, offset);

		uint64 reserved64 = 0;
		SerializeEntry (reserved64, header, offset);
		SerializeEntry (reserved64, header, offset);

		SerializeEntry (HiddenVolumeDataSize, header, offset);
		SerializeEntry (VolumeDataSize, header, offset);
		SerializeEntry (EncryptedAreaStart, header, offset);
		SerializeEntry (EncryptedAreaLength, header, offset);
		SerializeEntry (Flags, header, offset);

		if (SectorSize < TC_MIN_VOLUME_SECTOR_SIZE
			|| SectorSize > TC_MAX_VOLUME_SECTOR_SIZE
			|| SectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
		{
			throw ParameterIncorrect (SRC_POS);
		}

		SerializeEntry (SectorSize, header, offset);

		offset = TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC;
		SerializeEntry (Crc32::ProcessBuffer (header.GetRange (0, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC)), header, offset);
	}

	template <typename T>
	void VolumeHeader::SerializeEntry (const T &entry, const BufferPtr &header, size_t &offset) const
	{
		offset += sizeof (T);

		if (offset > header.Size())
			throw ParameterIncorrect (SRC_POS);

		*reinterpret_cast<T *> (header.Get() + offset - sizeof (T)) = Endian::Big (entry);
	}

	void VolumeHeader::SetSize (uint32 headerSize)
	{
		HeaderSize = headerSize;
		EncryptedHeaderDataSize = HeaderSize - EncryptedHeaderDataOffset;
	}
}
