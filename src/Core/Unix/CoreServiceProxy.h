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

#ifndef TC_HEADER_Core_Windows_CoreServiceProxy
#define TC_HEADER_Core_Windows_CoreServiceProxy

#include "CoreService.h"
#include "Volume/VolumePasswordCache.h"

namespace VeraCrypt
{
	template <class T>
	class CoreServiceProxy : public T
	{
	public:
		CoreServiceProxy () { }
		virtual ~CoreServiceProxy () { }

		virtual void CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair) const
		{
#ifdef TC_MACOSX
			// On macOS the check runs diskutil against the VeraCrypt virtual device
			// and shows the result in a Terminal window; neither needs root. Run it
			// in this (unprivileged) application process directly: once a device-hosted
			// mount has started the elevated core service, every request is routed to
			// that root process, which would create the helper script as root and open
			// a Terminal the GUI-session user cannot read or execute.
			T::CheckFilesystem (mountedVolume, repair);
#else
			CoreService::RequestCheckFilesystem (mountedVolume, repair);
#endif
		}

		virtual void DismountFilesystem (const DirectoryPath &mountPoint, bool force) const
		{
			CoreService::RequestDismountFilesystem (mountPoint, force);
		}

		virtual shared_ptr <VolumeInfo> DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles = false, bool syncVolumeInfo = false)
		{
			shared_ptr <VolumeInfo> dismountedVolumeInfo = CoreService::RequestDismountVolume (mountedVolume, ignoreOpenFiles, syncVolumeInfo);

			VolumeEventArgs eventArgs (dismountedVolumeInfo);
			T::VolumeDismountedEvent.Raise (eventArgs);

			return dismountedVolumeInfo;
		}

#ifdef TC_LINUX
		virtual shared_ptr <VolumeInfo> EmergencyDismountVolume (shared_ptr <VolumeInfo> mountedVolume)
		{
			shared_ptr <VolumeInfo> dismountedVolumeInfo = CoreService::RequestEmergencyDismountVolume (mountedVolume);

			VolumeEventArgs eventArgs (dismountedVolumeInfo);
			T::VolumeDismountedEvent.Raise (eventArgs);

			return dismountedVolumeInfo;
		}
#endif

		virtual uint32 GetDeviceSectorSize (const DevicePath &devicePath) const
		{
			return CoreService::RequestGetDeviceSectorSize (devicePath);
		}

		virtual uint64 GetDeviceSize (const DevicePath &devicePath) const
		{
			return CoreService::RequestGetDeviceSize (devicePath);
		}

#ifndef TC_LINUX
		virtual HostDeviceList GetHostDevices (bool pathListOnly = false) const
		{
			if (pathListOnly)
				return T::GetHostDevices (pathListOnly);
			else
				return CoreService::RequestGetHostDevices (pathListOnly);
		}
#endif
		virtual bool IsPasswordCacheEmpty () const { return VolumePasswordCache::IsEmpty(); }

		virtual shared_ptr <VolumeInfo> MountVolume (MountOptions &options)
		{
			shared_ptr <VolumeInfo> mountedVolume;
			FavoritePasswordCache::Snapshot favoritePasswords;
			if (options.FavoritePasswords)
				favoritePasswords = options.FavoritePasswords->GetSnapshot();
			const bool useCachedPasswords = (!favoritePasswords.Entries.empty() || !VolumePasswordCache::IsEmpty())
				&& (!options.Password || options.Password->IsEmpty())
				&& (!options.Keyfiles || options.Keyfiles->empty());
			MountOptions newOptions = options;

			// Resolve keyfiles in the application process, also when the outer password
			// is cached. Token access must not initialize PC/SC in the core service
			// before it forks FUSE.
			if (!useCachedPasswords)
				newOptions.Password = Keyfile::ApplyListToPassword (options.Keyfiles, options.Password, options.EMVSupportEnabled);
			if (newOptions.Keyfiles)
				newOptions.Keyfiles->clear();

			if (options.Protection == VolumeProtection::HiddenVolumeReadOnly)
				newOptions.ProtectionPassword = Keyfile::ApplyListToPassword (options.ProtectionKeyfiles, options.ProtectionPassword, options.EMVSupportEnabled);
			else
				newOptions.ProtectionPassword.reset();
			if (newOptions.ProtectionKeyfiles)
				newOptions.ProtectionKeyfiles->clear();

			try
			{
				if (useCachedPasswords)
				{
					finally_do_arg (MountOptions*, &options, { if (finally_arg->Password) finally_arg->Password.reset(); });

					PasswordIncorrect passwordException;
					list <FavoritePasswordCache::Entry> attempted;
					foreach (shared_ptr <FavoritePasswordCache::Entry> credential, favoritePasswords.Entries)
					{
						if (!options.FavoritePasswords->IsCurrent (favoritePasswords.Generation))
							break;
						// A remembered PIM is tried only with its successful KDF,
						// never with autodetection or a different selected KDF.
						if (credential->SystemEncryption != options.PartitionInSystemEncryptionScope
							|| (options.Kdf && options.Kdf->GetName() != credential->Kdf->GetName()))
							continue;

						newOptions.Pim = options.Pim < 0 ? credential->Pim : options.Pim;
						newOptions.Kdf = credential->Kdf;
						FavoritePasswordCache::Entry attempt (credential->Password, newOptions.Pim, newOptions.Kdf, options.PartitionInSystemEncryptionScope);
						bool duplicate = false;
						foreach (const FavoritePasswordCache::Entry &previous, attempted)
							if (attempt.Matches (previous)) duplicate = true;
						if (duplicate)
							continue;
						attempted.push_back (attempt);

						try
						{
							newOptions.Password = make_shared <VolumePassword> (credential->Password);
							mountedVolume = CoreService::RequestMountVolume (newOptions);
							break;
						}
						catch (ProtectionPasswordIncorrect&) { throw; }
						catch (ProtectionPasswordKeyfilesIncorrect&) { throw; }
						catch (PasswordIncorrect &e) { passwordException = e; }
						catch (PasswordOrKeyboardLayoutIncorrect&) { }
						catch (PasswordOrMountOptionsIncorrect&) { }
					}

					if (!mountedVolume)
					{
						// Ordinary cache attempts keep the original mount parameters
						// and exception handling, including when temporary reuse is off.
						newOptions.Pim = options.Pim;
						newOptions.Kdf = options.Kdf;
						foreach (shared_ptr <VolumePassword> password, VolumePasswordCache::GetPasswords())
						{
							bool duplicate = false;
							FavoritePasswordCache::Entry attempt (*password, options.Pim, options.Kdf, options.PartitionInSystemEncryptionScope);
							foreach (const FavoritePasswordCache::Entry &previous, attempted)
								if (attempt.Matches (previous)) duplicate = true;
							if (duplicate)
								continue;
							try
							{
								newOptions.Password = password;
								mountedVolume = CoreService::RequestMountVolume (newOptions);
								break;
							}
							catch (ProtectionPasswordIncorrect&)
							{
								// The outer password was accepted; another cached password cannot
								// correct the hidden-volume protection credentials.
								throw;
							}
							catch (ProtectionPasswordKeyfilesIncorrect&)
							{
								throw;
							}
							catch (PasswordIncorrect &e)
							{
								passwordException = e;
							}
						}
					}

					if (!mountedVolume)
						passwordException.Throw();
				}
				else
				{
					mountedVolume = CoreService::RequestMountVolume (newOptions);
				}
			}
			catch (ProtectionPasswordIncorrect &e)
			{
				if (options.ProtectionKeyfiles && !options.ProtectionKeyfiles->empty())
					throw ProtectionPasswordKeyfilesIncorrect (e.what());
				throw;
			}
			catch (ProtectionPasswordKeyfilesIncorrect&)
			{
				throw;
			}
			catch (PasswordIncorrect &e)
			{
				if (options.Keyfiles && !options.Keyfiles->empty())
					throw PasswordKeyfilesIncorrect (e.what());
				throw;
			}

			if (!useCachedPasswords && options.CachePassword
				&& ((options.Password && !options.Password->IsEmpty()) || (options.Keyfiles && !options.Keyfiles->empty())))
			{
				VolumePasswordCache::Store (*newOptions.Password);
			}

			// Only explicitly supplied credentials are learned; cache hits don't
			// acquire a PIM/KDF association or change the temporary cache order.
			if (options.FavoritePasswords && !useCachedPasswords && newOptions.Password && !newOptions.Password->IsEmpty())
			{
				shared_ptr <Pkcs5Kdf> kdf;
				try { kdf = Pkcs5Kdf::GetAlgorithm (mountedVolume->Pkcs5PrfName); }
				catch (ParameterIncorrect&) { }
				options.FavoritePasswords->Store (*newOptions.Password, mountedVolume->Pim, kdf,
					options.PartitionInSystemEncryptionScope, favoritePasswords.Generation);
			}

			VolumeEventArgs eventArgs (mountedVolume);
			T::VolumeMountedEvent.Raise (eventArgs);

			return mountedVolume;
		}

		virtual void SetAdminPasswordCallback (shared_ptr <GetStringFunctor> functor)
		{
			CoreService::SetAdminPasswordCallback (functor);
		}

		virtual void SetFileOwner (const FilesystemPath &path, const UserId &owner) const
		{
			CoreService::RequestSetFileOwner (path, owner);
		}

		virtual void WipePasswordCache () const
		{
			VolumePasswordCache::Clear();
			FavoritePasswordCache::ClearAll();
		}
	};
}

#endif // TC_HEADER_Core_Windows_CoreServiceProxy
