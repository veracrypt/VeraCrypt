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

#include "Platform/Serializer.h"
#include "Common/SecurityToken.h"
#include "Platform/PipelineStream.h"
#include "Platform/FileStream.h"
#include "Platform/AtomicFile.h"
#include "Crc32.h"
#include "Keyfile.h"
#include "VolumeException.h"

#ifdef TC_UNIX
#include <sys/stat.h>
#endif
namespace VeraCrypt
{
	namespace
	{
		class WipeVector
		{
		public:
			explicit WipeVector (vector<uint8> &data) : Data (data) { }
			~WipeVector () { if (!Data.empty()) burn (Data.data(), Data.size()); }
		private:
			vector<uint8> &Data;
			WipeVector (const WipeVector &);
			WipeVector &operator= (const WipeVector &);
		};

		// Keyfile plaintext must not outlive its stream in an ordinary vector.
		class KeyfileBufferStream : public Stream
		{
		public:
			explicit KeyfileBufferStream (const ConstBufferPtr &data) : Data (data), Position (0) { }
			uint64 Read (const BufferPtr &buffer)
			{
				size_t length = std::min (buffer.Size(), Data.Size() - Position);
				if (length != 0)
					buffer.CopyFrom (Data.GetRange (Position, length));
				Position += length;
				return length;
			}
			void ReadCompleteBuffer (const BufferPtr &buffer)
			{
				if (Read (buffer) != buffer.Size())
					throw InsufficientData (SRC_POS);
			}
			void Write (const ConstBufferPtr &) { throw NotApplicable (SRC_POS); }
		private:
			SecureBuffer Data;
			size_t Position;
		};

		void ValidateScheme (const SecurityTokenScheme &scheme)
		{
			if (scheme.DecryptOutputSize < Keyfile::MinProcessedLength
				|| scheme.DecryptOutputSize > Keyfile::MaxProcessedLength
				|| scheme.EncryptOutputSize <= scheme.DecryptOutputSize
				|| scheme.EncryptOutputSize > Keyfile::MaxProcessedLength)
				throw ParameterIncorrect (SRC_POS);
		}

		void CheckSeparateOutput (const FilePath &source, const FilePath &destination)
		{
			if (source == destination)
				throw ParameterIncorrect (SRC_POS, destination);
#ifdef TC_UNIX
			struct stat sourceStat, destinationStat;
			throw_sys_sub_if (stat (string (source).c_str(), &sourceStat) != 0, wstring (source));
			if (stat (string (destination).c_str(), &destinationStat) == 0
				&& sourceStat.st_dev == destinationStat.st_dev && sourceStat.st_ino == destinationStat.st_ino)
				throw ParameterIncorrect (SRC_POS, destination);
#endif
		}
	}

	void Keyfile::Apply (const BufferPtr &pool, wstring tokenKeyDescriptor, bool emvSupportEnabled) const
	{
		if (Path.IsDirectory() || pool.Size() == 0 || pool.Size() % 4 != 0)
			throw ParameterIncorrect (SRC_POS);

		Crc32 crc32;
		size_t poolPos = 0;
		size_t totalLength = 0;
		shared_ptr<Stream> stream = PrepareStream (tokenKeyDescriptor, emvSupportEnabled);
		SecureBuffer keyfileBuf (File::GetOptimalReadSize());

		while (totalLength < MaxProcessedLength)
		{
			size_t remaining = MaxProcessedLength - totalLength;
			uint64 readLength = stream->Read (keyfileBuf.GetRange (0, std::min (keyfileBuf.Size(), remaining)));
			if (readLength == 0)
				break;
			if (readLength > std::min (keyfileBuf.Size(), remaining))
				throw ParameterIncorrect (SRC_POS);

			for (size_t i = 0; i < readLength; ++i)
			{
				uint32 crc = crc32.Process (keyfileBuf[i]);
				pool[poolPos++] += (uint8) (crc >> 24);
				pool[poolPos++] += (uint8) (crc >> 16);
				pool[poolPos++] += (uint8) (crc >> 8);
				pool[poolPos++] += (uint8) crc;
				if (poolPos >= pool.Size())
					poolPos = 0;
			}
			totalLength += static_cast<size_t> (readLength);
		}

		if (totalLength < MinProcessedLength)
			throw InsufficientData (SRC_POS, Path);
	}


	shared_ptr <VolumePassword> Keyfile::ApplyListToPassword (shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> password,
		wstring tokenDescriptor, bool emvSupportEnabled)
	{
		if (!password)
			password.reset (new VolumePassword);

		if (!keyfiles || keyfiles->empty())
		{
			if (!tokenDescriptor.empty())
				throw ParameterIncorrect (SRC_POS);
			return password;
		}

		KeyfileList keyfilesExp;
		HiddenFileWasPresentInKeyfilePath = false;

		// Enumerate directories
		foreach (shared_ptr <Keyfile> keyfile, *keyfiles)
		{
			if (!keyfile)
				throw ParameterIncorrect (SRC_POS);
			if (FilesystemPath (*keyfile).IsDirectory())
			{
				size_t keyfileCount = 0;
				foreach_ref (const FilePath &path, Directory::GetFilePaths (*keyfile))
				{
#ifdef TC_UNIX
					// Skip hidden files
					if (wstring (path.ToBaseName()).find (L'.') == 0)
					{
						HiddenFileWasPresentInKeyfilePath = true;
						continue;
					}
#endif
					keyfilesExp.push_back (make_shared <Keyfile> (path));
					++keyfileCount;
				}

				if (keyfileCount == 0) {
					throw KeyfilePathEmpty (SRC_POS, FilesystemPath (*keyfile));
				}
			}
			else
			{
				keyfilesExp.push_back (keyfile);
			}
		}

		make_shared_auto (VolumePassword, newPassword);

		if (keyfilesExp.size() < 1)
		{
			newPassword->Set (*password);
		}
		else
		{
			SecureBuffer keyfilePool (password->Size() <= VolumePassword::MaxLegacySize? VolumePassword::MaxLegacySize: VolumePassword::MaxSize);

			// Pad password with zeros if shorter than max length
			keyfilePool.Zero();
			keyfilePool.CopyFrom (ConstBufferPtr (password->DataPtr(), password->Size()));

			// Apply all keyfiles
			foreach_ref (const Keyfile &k, keyfilesExp)
			{
				k.Apply (keyfilePool, tokenDescriptor, emvSupportEnabled);
			}

			newPassword->Set (keyfilePool);
		}

		return newPassword;
	}

	shared_ptr <KeyfileList> Keyfile::DeserializeList (shared_ptr <Stream> stream, const string &name)
	{
		shared_ptr <KeyfileList> keyfiles;
		Serializer sr (stream);

		if (!sr.DeserializeBool (name + "Null"))
		{
			keyfiles.reset (new KeyfileList);
			foreach (const wstring &k, sr.DeserializeWStringList (name))
				keyfiles->push_back (make_shared <Keyfile> (k));
		}
		return keyfiles;
	}

	void Keyfile::SerializeList (shared_ptr <Stream> stream, const string &name, shared_ptr <KeyfileList> keyfiles)
	{
		Serializer sr (stream);
		sr.Serialize (name + "Null", keyfiles == nullptr);
		if (keyfiles)
		{
			list <wstring> sl;

			foreach_ref (const Keyfile &k, *keyfiles)
				sl.push_back (FilesystemPath (k));

			sr.Serialize (name, sl);
		}
	}

	void Keyfile::CreateBluekey (FilePath bluekeyFile, wstring tokenSchemeDescriptor, SecureBuffer &buffer)
	{
		if (tokenSchemeDescriptor.empty())
			throw ParameterIncorrect (SRC_POS);

		SecurityTokenScheme scheme;
		SecurityToken::GetSecurityTokenScheme (tokenSchemeDescriptor, scheme, SecurityTokenKeyOperation::ENCRYPT);
		ValidateScheme (scheme);
		const size_t plaintextSize = scheme.DecryptOutputSize;
		if (buffer.Size() < plaintextSize)
			throw InsufficientData (SRC_POS);

		vector<uint8> plaintext (buffer.Ptr(), buffer.Ptr() + plaintextSize);
		WipeVector wipePlaintext (plaintext);
		vector<uint8> ciphertext;
		WipeVector wipeCiphertext (ciphertext);
		SecurityToken::GetEncryptedData (scheme, plaintext, ciphertext);
		if (ciphertext.size() != scheme.EncryptOutputSize)
			throw InsufficientData (SRC_POS);

		AtomicFile output (bluekeyFile);
		output.GetFile().Write (ConstBufferPtr (ciphertext.data(), ciphertext.size()));
		if (buffer.Size() > plaintextSize)
			output.GetFile().Write (buffer.GetRange (plaintextSize, buffer.Size() - plaintextSize));
		output.Commit();
	}

	void Keyfile::RevealRedkey (FilePath redkey, wstring tokenSchemeDescriptor)
	{
		if (tokenSchemeDescriptor.empty())
			throw ParameterIncorrect (SRC_POS);
		CheckSeparateOutput (Path, redkey);
		shared_ptr<Stream> stream = PrepareStream (tokenSchemeDescriptor, false);

		AtomicFile output (redkey);
		SecureBuffer buffer (File::GetOptimalReadSize());
		uint64 readLength;
		while ((readLength = stream->Read (buffer)) != 0)
			output.GetFile().Write (buffer, static_cast<size_t> (readLength));
		output.Commit();
	}

	shared_ptr<Stream> Keyfile::PrepareStream (wstring tokenSchemeDescriptor, bool emvSupportEnabled) const
	{
		if (Token::IsKeyfilePathValid (Path, emvSupportEnabled))
		{
			// A token object keyfile is already plaintext, not an encrypted disk keyfile.
			if (!tokenSchemeDescriptor.empty())
				throw ParameterIncorrect (SRC_POS, Path);
			vector<uint8> keyfileData;
			WipeVector wipeKeyfileData (keyfileData);
			Token::getTokenKeyfile (wstring (Path))->GetKeyfileData (keyfileData);
			if (keyfileData.size() < MinProcessedLength)
				throw InsufficientData (SRC_POS, Path);
			return make_shared<KeyfileBufferStream> (ConstBufferPtr (keyfileData.data(), keyfileData.size()));
		}

		shared_ptr<File> file = make_shared<File>();
		file->Open (Path, File::OpenRead, File::ShareRead);
		if (tokenSchemeDescriptor.empty())
			return make_shared<FileStream> (file);

		SecurityTokenScheme scheme;
		SecurityToken::GetSecurityTokenScheme (tokenSchemeDescriptor, scheme, SecurityTokenKeyOperation::DECRYPT);
		ValidateScheme (scheme);

		// Consume exactly the ciphertext prefix, leaving the plaintext remainder
		// at the current file position regardless of short reads or buffer sizes.
		vector<uint8> ciphertext (scheme.EncryptOutputSize);
		WipeVector wipeCiphertext (ciphertext);
		size_t position = 0;
		while (position < ciphertext.size())
		{
			uint64 readLength = file->Read (BufferPtr (ciphertext.data() + position, ciphertext.size() - position));
			if (readLength == 0)
				throw InsufficientData (SRC_POS, Path);
			position += static_cast<size_t> (readLength);
		}

		vector<uint8> plaintext;
		WipeVector wipePlaintext (plaintext);
		SecurityToken::GetDecryptedData (scheme, ciphertext, plaintext);
		if (plaintext.size() != scheme.DecryptOutputSize)
			throw InsufficientData (SRC_POS, Path);

		shared_ptr<PipelineStream> stream = make_shared<PipelineStream>();
		stream->AddStream (make_shared<KeyfileBufferStream> (ConstBufferPtr (plaintext.data(), plaintext.size())));
		stream->AddStream (make_shared<FileStream> (file));
		return stream;
	}

	bool Keyfile::HiddenFileWasPresentInKeyfilePath = false;
}
