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

#include "Platform/Finally.h"
#include "Platform/ForEach.h"

#if !defined (TC_WINDOWS) || defined (TC_PROTOTYPE)
#	include "Platform/SerializerFactory.h"
#	include "Platform/StringConverter.h"
#	include "Platform/SystemException.h"
#else
#	include "Dictionary.h"
#	include "Language.h"
#endif

#include <algorithm>
#include <limits>

#ifdef TC_UNIX
#	include <dlfcn.h>
#endif

#ifdef TC_WINDOWS
#define move_ptr	std::move
#endif

#include "SecurityToken.h"

using namespace std;

namespace VeraCrypt
{

	namespace
	{
		// Keyfiles contain RSA ciphertext, so bound allocation sizes independently
		// of lengths supplied by a PKCS #11 module.
		const size_t MaxRsaCiphertextSize = 2048; // RSA-16384

		bool IsUnavailableAttribute (CK_RV status)
		{
			return status == CKR_ATTRIBUTE_TYPE_INVALID || status == CKR_ATTRIBUTE_SENSITIVE;
		}

		template <class T> bool ReadScalarAttribute (SecurityTokenScheme &key, CK_ATTRIBUTE_TYPE type, T &value)
		{
			vector<uint8> attribute;
			SecurityToken::GetObjectAttribute (key, type, attribute);
			if (attribute.size() != sizeof (value))
				return false;
			memcpy (&value, attribute.data(), sizeof (value));
			return true;
		}

		bool ConfigureRsaScheme (SecurityTokenScheme &key, CK_MECHANISM_PTR mechanism, const wstring &label, size_t paddingSize)
		{
			CK_KEY_TYPE keyType;
			if (!ReadScalarAttribute (key, CKA_KEY_TYPE, keyType) || keyType != CKK_RSA)
				return false;

			CK_MECHANISM_INFO info;
			if (!SecurityToken::GetMechanismInfo (key.SlotId, mechanism->mechanism, &info)
				|| !(info.flags & (key.Operation == ENCRYPT ? CKF_ENCRYPT : CKF_DECRYPT)))
				return false;

			// CKA_MODULUS_BITS belongs to public keys; CKA_MODULUS is defined for
			// both public and private RSA keys and contains no private material.
			vector<uint8> modulus;
			SecurityToken::GetObjectAttribute (key, CKA_MODULUS, modulus);
			size_t first = 0;
			while (first < modulus.size() && modulus[first] == 0)
				++first;
			size_t bytes = modulus.size() - first;
			if (bytes == 0 || bytes > MaxRsaCiphertextSize)
				return false;
			size_t bits = (bytes - 1) * 8;
			for (uint8 high = modulus[first]; high != 0; high >>= 1)
				++bits;
			if (bits < 2048 || bits < info.ulMinKeySize || bits > info.ulMaxKeySize || bytes <= paddingSize)
				return false;

			key.DecryptOutputSize = bytes - paddingSize;
			key.EncryptOutputSize = bytes;
			key.Mechanism = mechanism;
			key.MechanismLabel = label;
			return true;
		}

		wstring HexEncode (const uint8 *data, size_t size)
		{
			static const wchar_t digits[] = L"0123456789abcdef";
			wstring result;
			for (size_t i = 0; i < size; ++i)
			{
				result += digits[data[i] >> 4];
				result += digits[data[i] & 15];
			}
			return result;
		}

		vector<uint8> HexDecode (const wstring &text)
		{
			if (text.empty() || text.size() % 2 != 0 || text.size() > 8192)
				throw InvalidSecurityTokenKeyfilePath();
			vector<uint8> result (text.size() / 2);
			for (size_t i = 0; i < text.size(); ++i)
			{
				wchar_t c = text[i];
				int digit = c >= L'0' && c <= L'9' ? c - L'0' :
					c >= L'a' && c <= L'f' ? c - L'a' + 10 :
					c >= L'A' && c <= L'F' ? c - L'A' + 10 : -1;
				if (digit < 0)
					throw InvalidSecurityTokenKeyfilePath();
				result[i / 2] = static_cast<uint8> ((result[i / 2] << 4) | digit);
			}
			return result;
		}

		CK_SLOT_ID ParseSlotId (const wstring &text)
		{
			if (text.empty())
				throw InvalidSecurityTokenKeyfilePath();
			CK_SLOT_ID value = 0;
			for (size_t i = 0; i < text.size(); ++i)
			{
				if (text[i] < L'0' || text[i] > L'9'
					|| value > ((numeric_limits<CK_SLOT_ID>::max)() - (text[i] - L'0')) / 10)
					throw InvalidSecurityTokenKeyfilePath();
				value = value * 10 + text[i] - L'0';
			}
			return value;
		}
	}

	MechanismList SecurityTokenMechanism::GetAvailableMechanisms ()
	{
		MechanismList mechanisms;
		mechanisms.push_back (make_shared<RSAOAEPSecurityTokenMechanism>());
		return mechanisms;
	}

	CK_MECHANISM RSASecurityTokenMechanism::_MECHANISM = { CKM_RSA_PKCS, NULL_PTR, 0 };

	bool RSASecurityTokenMechanism::ApplyTo (SecurityTokenScheme &key)
	{
		return ConfigureRsaScheme (key, &_MECHANISM, GetLabel(), 11);
	}

	CK_RSA_PKCS_OAEP_PARAMS RSAOAEPSecurityTokenMechanism::_OAEP_PARAMS = { CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
	CK_MECHANISM RSAOAEPSecurityTokenMechanism::_MECHANISM = { CKM_RSA_PKCS_OAEP, &_OAEP_PARAMS, sizeof (_OAEP_PARAMS) };

	bool RSAOAEPSecurityTokenMechanism::ApplyTo (SecurityTokenScheme &key)
	{
		return ConfigureRsaScheme (key, &_MECHANISM, GetLabel(), 2 + 2 * 32);
	}

	wstring SecurityTokenScheme::GetSpec() const
	{
		wstringstream result;
		if (!ObjectId.empty())
		{
			if (!Token.SerialNumber.empty())
				result << L"token-key:" << HexEncode (reinterpret_cast<const uint8 *> (Token.SerialNumber.data()), Token.SerialNumber.size());
			else
				result << L"slot-key:" << SlotId;
			result << L":" << HexEncode (ObjectId.data(), ObjectId.size()) << L":" << MechanismLabel;
		}
		else
			result << SlotId << L":" << Id << L":" << MechanismLabel;
		return result.str();
	}


	SecurityTokenKeyfile::SecurityTokenKeyfile(): Handle(CK_INVALID_HANDLE) {
		SecurityTokenInfo* token = new SecurityTokenInfo();
		Token = shared_ptr<SecurityTokenInfo>(token);
		Token->SlotId = CK_UNAVAILABLE_INFORMATION;
		token->Flags = 0;
	}

	SecurityTokenKeyfile::SecurityTokenKeyfile(const TokenKeyfilePath& path)
	{
		Token = shared_ptr<SecurityTokenInfo>(new SecurityTokenInfo());
		wstring pathStr = path;
		unsigned long slotId;

		if (swscanf(pathStr.c_str(), TC_SECURITY_TOKEN_KEYFILE_URL_PREFIX TC_SECURITY_TOKEN_KEYFILE_URL_SLOT L"/%lu", &slotId) != 1)
			throw InvalidSecurityTokenKeyfilePath();

		Token->SlotId = slotId;

		size_t keyIdPos = pathStr.find(L"/" TC_SECURITY_TOKEN_KEYFILE_URL_FILE L"/");
		if (keyIdPos == wstring::npos)
			throw InvalidSecurityTokenKeyfilePath();

		Id = pathStr.substr(keyIdPos + wstring(L"/" TC_SECURITY_TOKEN_KEYFILE_URL_FILE L"/").size());

		vector <SecurityTokenKeyfile> keyfiles = SecurityToken::GetAvailableKeyfiles(&Token->SlotId, Id);

		if (keyfiles.empty())
			throw SecurityTokenKeyfileNotFound();

		*this = keyfiles.front();
	}

	SecurityTokenKeyfile::operator TokenKeyfilePath () const
	{
		wstringstream path;
		path << TC_SECURITY_TOKEN_KEYFILE_URL_PREFIX TC_SECURITY_TOKEN_KEYFILE_URL_SLOT L"/" << Token->SlotId << L"/" TC_SECURITY_TOKEN_KEYFILE_URL_FILE L"/" << Id;
		return path.str();
	}

	void SecurityTokenImpl::CheckLibraryStatus ()
	{
		if (!Initialized)
			throw SecurityTokenLibraryNotInitialized();
	}

	void SecurityTokenImpl::CloseLibrary ()
	{
		if (Initialized)
		{
			CloseAllSessions();
			Pkcs11Functions->C_Finalize(NULL_PTR);

#ifdef TC_WINDOWS
			FreeLibrary(Pkcs11LibraryHandle);
#else
			dlclose(Pkcs11LibraryHandle);
#endif
			Initialized = false;
			Pkcs11Functions = NULL_PTR;
			Pkcs11LibraryHandle = nullptr;
			PinCallback.reset();
			WarningCallback.reset();
		}
	}

	void SecurityTokenImpl::CloseAllSessions () throw ()
	{
		if (!Initialized)
			return;

		while (!Sessions.empty())
		{
			Pkcs11Functions->C_CloseSession (Sessions.begin()->second.Handle);
			Sessions.erase (Sessions.begin());
		}
	}

	void SecurityTokenImpl::CloseSession (CK_SLOT_ID slotId)
	{
		if (Sessions.find(slotId) == Sessions.end())
			throw ParameterIncorrect(SRC_POS);

		Pkcs11Functions->C_CloseSession(Sessions[slotId].Handle);
		Sessions.erase(Sessions.find(slotId));
	}

	void SecurityTokenImpl::CreateKeyfile (CK_SLOT_ID slotId, vector <uint8> &keyfileData, const string &name)
	{
		if (name.empty() || keyfileData.empty() || name.size() > (numeric_limits<CK_ULONG>::max)() || keyfileData.size() > (numeric_limits<CK_ULONG>::max)())
			throw ParameterIncorrect(SRC_POS);

		LoginUserIfRequired(slotId);

		foreach(const SecurityTokenKeyfile & keyfile, GetAvailableKeyfiles(&slotId))
		{
			if (keyfile.IdUtf8 == name)
				throw SecurityTokenKeyfileAlreadyExists();
		}

		CK_OBJECT_CLASS dataClass = CKO_DATA;
		CK_BBOOL trueVal = CK_TRUE;

		CK_ATTRIBUTE keyfileTemplate[] =
		{
			{ CKA_CLASS, &dataClass, sizeof(dataClass) },
			{ CKA_TOKEN, &trueVal, sizeof(trueVal) },
			{ CKA_PRIVATE, &trueVal, sizeof(trueVal) },
			{ CKA_LABEL, (CK_UTF8CHAR*)name.c_str(), (CK_ULONG)name.size() },
			{ CKA_VALUE, &keyfileData.front(), (CK_ULONG)keyfileData.size() }
		};

		CK_OBJECT_HANDLE keyfileHandle;

		CK_RV status = Pkcs11Functions->C_CreateObject(Sessions[slotId].Handle, keyfileTemplate, array_capacity(keyfileTemplate), &keyfileHandle);

		switch (status)
		{
		case CKR_DATA_LEN_RANGE:
			status = CKR_DEVICE_MEMORY;
			break;

		case CKR_SESSION_READ_ONLY:
			status = CKR_TOKEN_WRITE_PROTECTED;
			break;
		}

		if (status != CKR_OK)
			throw Pkcs11Exception(status);

		// Some tokens report success even if the new object was truncated to fit in the available memory
		vector <uint8> objectData;

		GetObjectAttribute(slotId, keyfileHandle, CKA_VALUE, objectData);
		finally_do_arg(vector <uint8> *, &objectData, { if (!finally_arg->empty()) burn(&finally_arg->front(), finally_arg->size()); });

		if (objectData.size() != keyfileData.size())
		{
			Pkcs11Functions->C_DestroyObject(Sessions[slotId].Handle, keyfileHandle);
			throw Pkcs11Exception(CKR_DEVICE_MEMORY);
		}
	}

	void SecurityTokenImpl::DeleteKeyfile (const SecurityTokenKeyfile &keyfile)
	{
		LoginUserIfRequired(keyfile.Token->SlotId);

		CK_RV status = Pkcs11Functions->C_DestroyObject(Sessions[keyfile.Token->SlotId].Handle, keyfile.Handle);
		if (status != CKR_OK)
			throw Pkcs11Exception(status);
	}


	void SecurityTokenImpl::GetSecurityTokenScheme (wstring descriptor, SecurityTokenScheme &key, SecurityTokenKeyOperation mode)
	{
		if (mode != ENCRYPT && mode != DECRYPT)
			throw ParameterIncorrect (SRC_POS);
		if (descriptor.size() > 16384)
			throw InvalidSecurityTokenKeyfilePath();

		bool serialDescriptor = descriptor.find (L"token-key:") == 0;
		bool idDescriptor = serialDescriptor || descriptor.find (L"slot-key:") == 0;
		if (idDescriptor)
			descriptor.erase (0, serialDescriptor ? 10 : 9);
		size_t firstColon = descriptor.find (L':');
		size_t lastColon = descriptor.rfind (L':');
		if (firstColon == wstring::npos || firstColon == lastColon || lastColon + 1 == descriptor.size())
			throw InvalidSecurityTokenKeyfilePath();

		wstring mechanism = descriptor.substr (lastColon + 1);
		if (mechanism != RSAOAEPSecurityTokenMechanism::GetLabel())
			throw Pkcs11Exception (CKR_MECHANISM_INVALID);
		wstring identity = descriptor.substr (firstColon + 1, lastColon - firstColon - 1);
		if (identity.empty())
			throw InvalidSecurityTokenKeyfilePath();
		vector<uint8> objectId;
		if (idDescriptor)
			objectId = HexDecode (identity);

		CK_SLOT_ID slotId = CK_UNAVAILABLE_INFORMATION;
		if (serialDescriptor)
		{
			vector<uint8> serialBytes = HexDecode (descriptor.substr (0, firstColon));
			string serial (serialBytes.begin(), serialBytes.end());
			bool found = false;
			foreach (const CK_SLOT_ID &candidate, GetTokenSlots())
			{
				if (GetTokenInfo (candidate).SerialNumber == serial)
				{
					if (found)
						throw Pkcs11Exception (CKR_KEY_NEEDED);
					found = true;
					slotId = candidate;
				}
			}
			if (!found)
				throw Pkcs11Exception (CKR_TOKEN_NOT_PRESENT);
		}
		else
			slotId = ParseSlotId (descriptor.substr (0, firstColon));

		vector<SecurityTokenScheme> keys = GetAvailableKeys (&slotId, idDescriptor ? wstring() : identity,
			mechanism, mode, idDescriptor ? &objectId : NULL_PTR);
		if (keys.size() != 1)
			throw Pkcs11Exception (CKR_KEY_NEEDED);
		key = keys.front();
	}

	vector<SecurityTokenScheme> SecurityTokenImpl::GetAvailablePrivateKeys (CK_SLOT_ID *slotIdFilter, const wstring keyIdFilter, const wstring mechanismLabel)
	{
		return GetAvailableKeys (slotIdFilter, keyIdFilter, mechanismLabel, DECRYPT);
	}

	vector<SecurityTokenScheme> SecurityTokenImpl::GetAvailablePublicKeys (CK_SLOT_ID *slotIdFilter, const wstring keyIdFilter, const wstring mechanismLabel)
	{
		return GetAvailableKeys (slotIdFilter, keyIdFilter, mechanismLabel, ENCRYPT);
	}

	vector<SecurityTokenScheme> SecurityTokenImpl::GetAvailableKeys (CK_SLOT_ID *slotIdFilter, const wstring &keyIdFilter,
		const wstring &mechanismLabel, SecurityTokenKeyOperation operation, const vector<uint8> *objectIdFilter)
	{
		bool unrecognizedTokenPresent = false;
		vector<SecurityTokenScheme> keys;
		MechanismList mechanisms = SecurityTokenMechanism::GetAvailableMechanisms();
		foreach (const CK_SLOT_ID &slotId, GetTokenSlots())
		{
			if (slotIdFilter && *slotIdFilter != slotId)
				continue;
			SecurityTokenInfo token;
			try
			{
				LoginUserIfRequired (slotId);
				token = GetTokenInfo (slotId);
			}
			catch (UserAbort &)
			{
				if (slotIdFilter)
					throw;
				continue;
			}
			catch (Pkcs11Exception &e)
			{
				if (e.GetErrorCode() == CKR_TOKEN_NOT_RECOGNIZED)
				{
					unrecognizedTokenPresent = true;
					continue;
				}
				throw;
			}

			foreach (const CK_OBJECT_HANDLE &handle, GetObjects (slotId, operation == ENCRYPT ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY))
			{
				try
				{
					SecurityTokenScheme key;
					key.Handle = handle;
					key.SlotId = slotId;
					key.SessionHandle = Sessions[slotId].Handle;
					key.SessionGeneration = Sessions[slotId].Generation;
					key.Operation = operation;
					key.Token = token;
					CK_BBOOL permitted;
					if (!ReadScalarAttribute (key, operation == ENCRYPT ? CKA_ENCRYPT : CKA_DECRYPT, permitted) || permitted != CK_TRUE)
						continue;

					GetObjectAttribute (slotId, handle, CKA_ID, key.ObjectId);
					if (key.ObjectId.size() > 4096 || (objectIdFilter && key.ObjectId != *objectIdFilter))
						continue;
					vector<uint8> label;
					GetObjectAttribute (slotId, handle, CKA_LABEL, label);
					// Embedded NULs cannot be represented faithfully by the legacy label format.
					if (find (label.begin(), label.end(), 0) != label.end())
						continue;
					key.IdUtf8.assign (label.begin(), label.end());
#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
					key.Id = Utf8StringToWide (key.IdUtf8);
#else
					key.Id = StringConverter::ToWide (key.IdUtf8);
#endif
					if ((!keyIdFilter.empty() && key.Id != keyIdFilter) || (key.Id.empty() && key.ObjectId.empty()))
						continue;
					if (key.Id.empty())
						key.Id = L"ID " + HexEncode (key.ObjectId.data(), key.ObjectId.size());

					foreach (const shared_ptr<SecurityTokenMechanism> &mechanism, mechanisms)
					{
						if (mechanism->ApplyTo (key) && (mechanismLabel.empty() || mechanismLabel == key.MechanismLabel))
							keys.push_back (key);
					}
				}
				catch (Pkcs11Exception &e)
				{
					// Mixed tokens commonly expose EC, signing-only and unavailable keys.
					// An unsupported attribute on one object must not hide usable RSA keys.
					if (!IsUnavailableAttribute (e.GetErrorCode()))
						throw;
				}
			}
		}
		if (keys.empty() && unrecognizedTokenPresent)
			throw Pkcs11Exception (CKR_TOKEN_NOT_RECOGNIZED);
		return keys;
	}

	vector <SecurityTokenKeyfile> SecurityTokenImpl::GetAvailableKeyfiles (CK_SLOT_ID *slotIdFilter, const wstring keyfileIdFilter)
	{
		bool unrecognizedTokenPresent = false;
		vector <SecurityTokenKeyfile> keyfiles;

		foreach(const CK_SLOT_ID & slotId, GetTokenSlots())
		{
			SecurityTokenInfo token;

			if (slotIdFilter && *slotIdFilter != slotId)
				continue;

			try
			{
				LoginUserIfRequired(slotId);
				token = GetTokenInfo(slotId);
			}
			catch (UserAbort&)
			{
				continue;
			}
			catch (Pkcs11Exception& e)
			{
				if (e.GetErrorCode() == CKR_TOKEN_NOT_RECOGNIZED)
				{
					unrecognizedTokenPresent = true;
					continue;
				}

				throw;
			}

			vector <CK_OBJECT_HANDLE> dataHandles = GetObjects(slotId, CKO_DATA);
			for (vector <CK_OBJECT_HANDLE>::const_iterator dataHandleIt = dataHandles.begin(); dataHandleIt != dataHandles.end(); ++dataHandleIt)
			{
				const CK_OBJECT_HANDLE &dataHandle = *dataHandleIt;
				SecurityTokenKeyfile keyfile;
				keyfile.Handle = dataHandle;
				keyfile.Token->SlotId = slotId;
				keyfile.Token = shared_ptr<SecurityTokenInfo>(new SecurityTokenInfo(token));

				vector <uint8> privateAttrib;
				GetObjectAttribute(slotId, dataHandle, CKA_PRIVATE, privateAttrib);

				if (privateAttrib.size() == sizeof(CK_BBOOL) && *(CK_BBOOL*)&privateAttrib.front() != CK_TRUE)
					continue;

				vector <uint8> label;
				GetObjectAttribute(slotId, dataHandle, CKA_LABEL, label);
				label.push_back(0);

				keyfile.IdUtf8 = (char*)&label.front();

#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
				keyfile.Id = Utf8StringToWide((const char*)&label.front());
#else
				keyfile.Id = StringConverter::ToWide((const char*)&label.front());
#endif
				if (keyfile.Id.empty() || (!keyfileIdFilter.empty() && keyfileIdFilter != keyfile.Id))
					continue;

				keyfiles.push_back(keyfile);

				if (!keyfileIdFilter.empty())
					break;
			}
		}

		if (keyfiles.empty() && unrecognizedTokenPresent)
			throw Pkcs11Exception(CKR_TOKEN_NOT_RECOGNIZED);

		return keyfiles;
	}

	list <SecurityTokenInfo> SecurityTokenImpl::GetAvailableTokens ()
	{
		bool unrecognizedTokenPresent = false;
		list <SecurityTokenInfo> tokens;

		foreach(const CK_SLOT_ID & slotId, GetTokenSlots())
		{
			try
			{
				tokens.push_back(GetTokenInfo(slotId));
			}
			catch (Pkcs11Exception& e)
			{
				if (e.GetErrorCode() == CKR_TOKEN_NOT_RECOGNIZED)
				{
					unrecognizedTokenPresent = true;
					continue;
				}

				throw;
			}
		}

		if (tokens.empty() && unrecognizedTokenPresent)
			throw Pkcs11Exception(CKR_TOKEN_NOT_RECOGNIZED);

		return tokens;
	}

	SecurityTokenInfo SecurityTokenImpl::GetTokenInfo (CK_SLOT_ID slotId)
	{
		CheckLibraryStatus();
		CK_TOKEN_INFO info;
		CK_RV status = Pkcs11Functions->C_GetTokenInfo(slotId, &info);
		if (status != CKR_OK)
			throw Pkcs11Exception(status);

		SecurityTokenInfo token;
		token.SlotId = slotId;
		token.Flags = info.flags;
		token.SerialNumber.assign (reinterpret_cast<const char *> (info.serialNumber), sizeof (info.serialNumber));
		size_t serialEnd = token.SerialNumber.find_last_not_of (' ');
		token.SerialNumber.resize (serialEnd == string::npos ? 0 : serialEnd + 1);

		char label[sizeof(info.label) + 1];
		memset(label, 0, sizeof(label));
		memcpy(label, info.label, sizeof(info.label));

		token.LabelUtf8 = label;

		size_t lastSpace = token.LabelUtf8.find_last_not_of(' ');
		if (lastSpace == string::npos)
			token.LabelUtf8.clear();
		else
			token.LabelUtf8 = token.LabelUtf8.substr(0, lastSpace + 1);

#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
		token.Label = Utf8StringToWide(token.LabelUtf8);
#else
		token.Label = StringConverter::ToWide(token.LabelUtf8);
#endif
		return token;
	}

	void SecurityTokenKeyfile::GetKeyfileData(vector <uint8>& keyfileData) const
	{
		SecurityToken::GetKeyfileData(*this, keyfileData);
	}

	void SecurityTokenImpl::GetKeyfileData (const SecurityTokenKeyfile &keyfile, vector <uint8> &keyfileData)
	{
		LoginUserIfRequired (keyfile.Token->SlotId);
		GetObjectAttribute (keyfile.Token->SlotId, keyfile.Handle, CKA_VALUE, keyfileData);
	}

	vector <CK_OBJECT_HANDLE> SecurityTokenImpl::GetObjects (CK_SLOT_ID slotId, CK_ATTRIBUTE_TYPE objectClass)
	{
		if (Sessions.find(slotId) == Sessions.end())
			throw ParameterIncorrect(SRC_POS);

		CK_ATTRIBUTE findTemplate;
		findTemplate.type = CKA_CLASS;
		findTemplate.pValue = &objectClass;
		findTemplate.ulValueLen = sizeof(objectClass);

		CK_RV status = Pkcs11Functions->C_FindObjectsInit(Sessions[slotId].Handle, &findTemplate, 1);
		if (status != CKR_OK)
			throw Pkcs11Exception(status);

		finally_do_member (SecurityTokenImpl, CK_SLOT_ID, slotId, { finally_obj->Pkcs11Functions->C_FindObjectsFinal (finally_obj->Sessions[finally_arg].Handle); });


		CK_ULONG objectCount;
		vector <CK_OBJECT_HANDLE> objects;

		while (true)
		{
			CK_OBJECT_HANDLE object;
			status = Pkcs11Functions->C_FindObjects(Sessions[slotId].Handle, &object, 1, &objectCount);
			if (status != CKR_OK)
				throw Pkcs11Exception(status);

			if (objectCount != 1)
				break;

			objects.push_back(object);
		}

		return objects;
	}


	void SecurityTokenImpl::GetEncryptedData (const SecurityTokenScheme &key, const vector<uint8> &plaintext, vector<uint8> &ciphertext)
	{
		if (&plaintext == &ciphertext || key.Operation != ENCRYPT || !key.Mechanism
			|| key.Mechanism->mechanism != CKM_RSA_PKCS_OAEP
			|| key.EncryptOutputSize < 256 || key.EncryptOutputSize > MaxRsaCiphertextSize
			|| key.DecryptOutputSize != key.EncryptOutputSize - 66
			|| plaintext.empty() || plaintext.size() > key.DecryptOutputSize)
			throw Pkcs11Exception (CKR_DATA_LEN_RANGE);
		ciphertext.clear();
		LoginUserIfRequired (key.SlotId);
		if (Sessions[key.SlotId].Handle != key.SessionHandle || Sessions[key.SlotId].Generation != key.SessionGeneration
			|| GetTokenInfo (key.SlotId).SerialNumber != key.Token.SerialNumber)
			throw Pkcs11Exception (CKR_KEY_CHANGED);

		bool complete = false;
		typedef pair<CK_SLOT_ID, bool *> OperationState;
		finally_do_arg2 (SecurityTokenImpl *, this, OperationState, make_pair (key.SlotId, &complete),
			{ if (!*finally_arg2.second) finally_arg->CloseSession (finally_arg2.first); });
		CK_MECHANISM mechanism = RSAOAEPSecurityTokenMechanism::GetMechanism();
		CK_RV status = Pkcs11Functions->C_EncryptInit (Sessions[key.SlotId].Handle, &mechanism, key.Handle);
		if (status != CKR_OK)
			throw Pkcs11Exception (status);

		vector<uint8> result (key.EncryptOutputSize);
		CK_ULONG length = static_cast<CK_ULONG> (result.size());
		status = Pkcs11Functions->C_Encrypt (Sessions[key.SlotId].Handle, const_cast<CK_BYTE_PTR> (plaintext.data()),
			static_cast<CK_ULONG> (plaintext.size()), result.data(), &length);
		if (status != CKR_OK)
			throw Pkcs11Exception (status);
		if (length != result.size())
			throw Pkcs11Exception (CKR_DATA_LEN_RANGE);
		complete = true;
		ciphertext.swap (result);
	}

	void SecurityTokenImpl::GetDecryptedData (const SecurityTokenScheme &key, const vector<uint8> &ciphertext, vector<uint8> &plaintext)
	{
		if (&ciphertext == &plaintext)
			throw ParameterIncorrect (SRC_POS);
		if (!plaintext.empty())
			burn (plaintext.data(), plaintext.size());
		plaintext.clear();
		if (key.Operation != DECRYPT || !key.Mechanism || key.Mechanism->mechanism != CKM_RSA_PKCS_OAEP
			|| key.EncryptOutputSize < 256 || key.EncryptOutputSize > MaxRsaCiphertextSize
			|| key.DecryptOutputSize != key.EncryptOutputSize - 66 || ciphertext.size() != key.EncryptOutputSize)
			throw Pkcs11Exception (CKR_ENCRYPTED_DATA_LEN_RANGE);
		LoginUserIfRequired (key.SlotId);
		if (Sessions[key.SlotId].Handle != key.SessionHandle || Sessions[key.SlotId].Generation != key.SessionGeneration
			|| GetTokenInfo (key.SlotId).SerialNumber != key.Token.SerialNumber)
			throw Pkcs11Exception (CKR_KEY_CHANGED);

		CK_BBOOL alwaysAuthenticate = CK_FALSE;
		try
		{
			vector<uint8> attribute;
			GetObjectAttribute (key.SlotId, key.Handle, CKA_ALWAYS_AUTHENTICATE, attribute);
			if (attribute.size() != sizeof (alwaysAuthenticate))
				throw Pkcs11Exception (CKR_ATTRIBUTE_VALUE_INVALID);
			memcpy (&alwaysAuthenticate, attribute.data(), sizeof (alwaysAuthenticate));
			if (alwaysAuthenticate != CK_TRUE && alwaysAuthenticate != CK_FALSE)
				throw Pkcs11Exception (CKR_ATTRIBUTE_VALUE_INVALID);
		}
		catch (Pkcs11Exception &e)
		{
			if (e.GetErrorCode() != CKR_ATTRIBUTE_TYPE_INVALID)
				throw;
		}

		bool complete = false;
		typedef pair<CK_SLOT_ID, bool *> OperationState;
		finally_do_arg2 (SecurityTokenImpl *, this, OperationState, make_pair (key.SlotId, &complete),
			{ if (!*finally_arg2.second) finally_arg->CloseSession (finally_arg2.first); });
		CK_MECHANISM mechanism = RSAOAEPSecurityTokenMechanism::GetMechanism();
		CK_RV status = Pkcs11Functions->C_DecryptInit (Sessions[key.SlotId].Handle, &mechanism, key.Handle);
		if (status != CKR_OK)
			throw Pkcs11Exception (status);
		if (alwaysAuthenticate == CK_TRUE)
			LoginContextSpecific (key.SlotId);

		// A modulus-sized buffer also accommodates modules returning the conservative
		// RSA output bound. Avoid a size-query call that can consume touch/PIN state.
		vector<uint8> result (key.EncryptOutputSize);
		finally_do_arg (vector<uint8> *, &result, { if (!finally_arg->empty()) burn (finally_arg->data(), finally_arg->size()); });
		CK_ULONG length = static_cast<CK_ULONG> (result.size());
		status = Pkcs11Functions->C_Decrypt (Sessions[key.SlotId].Handle, const_cast<CK_BYTE_PTR> (ciphertext.data()),
			static_cast<CK_ULONG> (ciphertext.size()), result.data(), &length);
		if (status != CKR_OK)
			throw Pkcs11Exception (status);
		if (length == 0 || length > key.DecryptOutputSize)
			throw Pkcs11Exception (CKR_ENCRYPTED_DATA_LEN_RANGE);
		burn (result.data() + length, result.size() - length);
		result.resize (length);
		complete = true;
		plaintext.swap (result);
	}

	void SecurityTokenImpl::GetObjectAttribute (CK_SLOT_ID slotId, CK_OBJECT_HANDLE tokenObject, CK_ATTRIBUTE_TYPE attributeType, vector<uint8> &attributeValue)
	{
		CheckLibraryStatus();
		if (!attributeValue.empty())
			burn (attributeValue.data(), attributeValue.size());
		attributeValue.clear();
		if (Sessions.find (slotId) == Sessions.end())
			throw ParameterIncorrect (SRC_POS);

		CK_ATTRIBUTE attribute = { attributeType, NULL_PTR, 0 };
		CK_RV status = Pkcs11Functions->C_GetAttributeValue (Sessions[slotId].Handle, tokenObject, &attribute, 1);
		if (status != CKR_OK)
			throw Pkcs11Exception (status);
		// Bound metadata independently of provider-supplied lengths. Legacy data
		// keyfiles may exceed one MiB: mounting mixes their prefix, but export must
		// preserve the complete CKA_VALUE object accepted by earlier releases.
		vector<uint8> result;
		if (attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION || attribute.ulValueLen > result.max_size()
			|| (attributeType != CKA_VALUE && attribute.ulValueLen > 1024 * 1024))
			throw Pkcs11Exception (CKR_ATTRIBUTE_VALUE_INVALID);
		if (attribute.ulValueLen == 0)
			return;
		result.resize (static_cast<size_t> (attribute.ulValueLen));
		finally_do_arg (vector<uint8> *, &result, { if (!finally_arg->empty()) burn (finally_arg->data(), finally_arg->size()); });
		attribute.pValue = result.data();
		status = Pkcs11Functions->C_GetAttributeValue (Sessions[slotId].Handle, tokenObject, &attribute, 1);
		if (status != CKR_OK)
			throw Pkcs11Exception (status);
		if (attribute.ulValueLen > result.size())
			throw Pkcs11Exception (CKR_ATTRIBUTE_VALUE_INVALID);
		burn (result.data() + attribute.ulValueLen, result.size() - attribute.ulValueLen);
		result.resize (attribute.ulValueLen);
		attributeValue.swap (result);
	}

	list <CK_SLOT_ID> SecurityTokenImpl::GetTokenSlots ()
	{
		CheckLibraryStatus();
		// Slot counts may change between the query and read when a token is inserted.
		for (unsigned int attempt = 0; attempt < 3; ++attempt)
		{
			CK_ULONG count = 0;
			CK_RV status = Pkcs11Functions->C_GetSlotList (TRUE, NULL_PTR, &count);
			if (status != CKR_OK)
				throw Pkcs11Exception (status);
			if (count > 65536)
				throw Pkcs11Exception (CKR_DEVICE_MEMORY);
			list<CK_SLOT_ID> slots;
			if (count == 0)
				return slots;
			vector<CK_SLOT_ID> slotArray (count);
			status = Pkcs11Functions->C_GetSlotList (TRUE, slotArray.data(), &count);
			if (status == CKR_BUFFER_TOO_SMALL)
				continue;
			if (status != CKR_OK)
				throw Pkcs11Exception (status);
			if (count > slotArray.size())
				throw Pkcs11Exception (CKR_DEVICE_ERROR);
			for (size_t i = 0; i < count; ++i)
			{
				CK_SLOT_INFO info;
				if (Pkcs11Functions->C_GetSlotInfo (slotArray[i], &info) == CKR_OK && (info.flags & CKF_TOKEN_PRESENT))
					slots.push_back (slotArray[i]);
			}
			return slots;
		}
		throw Pkcs11Exception (CKR_BUFFER_TOO_SMALL);
	}

	bool SecurityTokenImpl::GetMechanismInfo (CK_SLOT_ID slotId, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR mechanismInfo)
	{
		CheckLibraryStatus();
		if (!mechanismInfo)
			throw ParameterIncorrect (SRC_POS);
		CK_RV status = Pkcs11Functions->C_GetMechanismInfo (slotId, type, mechanismInfo);
		if (status == CKR_MECHANISM_INVALID)
			return false;
		if (status != CKR_OK)
			throw Pkcs11Exception (status);
		return true;
	}

	bool SecurityTokenImpl::IsKeyfilePathValid (const wstring &SecurityTokenKeyfilePath)
	{
		return SecurityTokenKeyfilePath.find(TC_SECURITY_TOKEN_KEYFILE_URL_PREFIX) == 0;
	}

	void SecurityTokenImpl::Login (CK_SLOT_ID slotId, const char* pin)
	{
		if (Sessions.find(slotId) == Sessions.end())
			OpenSession(slotId);
		else if (Sessions[slotId].UserLoggedIn)
			return;

		size_t pinLen = pin ? strlen(pin) : 0;
		CK_RV status = Pkcs11Functions->C_Login(Sessions[slotId].Handle, CKU_USER, (CK_CHAR_PTR)pin, (CK_ULONG)pinLen);

		if (status != CKR_OK && status != CKR_USER_ALREADY_LOGGED_IN)
			throw Pkcs11Exception(status);

		Sessions[slotId].UserLoggedIn = true;
	}

	void SecurityTokenImpl::LoginContextSpecific (CK_SLOT_ID slotId)
	{
		SecurityTokenInfo token = GetTokenInfo (slotId);
		CK_RV status;
		if (token.Flags & CKF_PROTECTED_AUTHENTICATION_PATH)
			status = Pkcs11Functions->C_Login (Sessions[slotId].Handle, CKU_CONTEXT_SPECIFIC, NULL_PTR, 0);
		else
		{
			if (!PinCallback)
				throw Pkcs11Exception (CKR_USER_NOT_LOGGED_IN);
			string pin = token.LabelUtf8;
			finally_do_arg (string *, &pin, { if (!finally_arg->empty()) burn (&(*finally_arg)[0], finally_arg->size()); });
			(*PinCallback) (pin);
			if (pin.size() > (numeric_limits<CK_ULONG>::max)())
				throw Pkcs11Exception (CKR_PIN_LEN_RANGE);
			status = Pkcs11Functions->C_Login (Sessions[slotId].Handle, CKU_CONTEXT_SPECIFIC,
				reinterpret_cast<CK_UTF8CHAR_PTR> (const_cast<char *> (pin.c_str())), static_cast<CK_ULONG> (pin.size()));
			if (status == CKR_PIN_INCORRECT)
				PinCallback->notifyIncorrectPin();
		}
		if (status != CKR_OK)
			throw Pkcs11Exception (status);
	}

	void SecurityTokenImpl::LoginUserIfRequired (CK_SLOT_ID slotId)
	{
		CheckLibraryStatus();

		CK_RV status;

		if (Sessions.find(slotId) == Sessions.end())
		{
			OpenSession(slotId);
		}
		else
		{
			CK_SESSION_INFO sessionInfo;
			status = Pkcs11Functions->C_GetSessionInfo(Sessions[slotId].Handle, &sessionInfo);

			if (status == CKR_OK)
			{
				Sessions[slotId].UserLoggedIn = (sessionInfo.state == CKS_RO_USER_FUNCTIONS || sessionInfo.state == CKS_RW_USER_FUNCTIONS);
			}
			else
			{
				try
				{
					CloseSession(slotId);
				}
				catch (...) {}
				OpenSession(slotId);
			}
		}

		SecurityTokenInfo tokenInfo = GetTokenInfo(slotId);

		while (!Sessions[slotId].UserLoggedIn && (tokenInfo.Flags & CKF_LOGIN_REQUIRED))
		{
			try
			{
				if (tokenInfo.Flags & CKF_PROTECTED_AUTHENTICATION_PATH)
				{
					status = Pkcs11Functions->C_Login(Sessions[slotId].Handle, CKU_USER, NULL_PTR, 0);
					if (status != CKR_OK)
						throw Pkcs11Exception(status);
				}
				else
				{
					string pin = tokenInfo.LabelUtf8;
					if (tokenInfo.Label.empty())
					{
						stringstream s;
						s << "#" << slotId;
						pin = s.str();
					}

					finally_do_arg(string*, &pin, { burn((void*)finally_arg->c_str(), finally_arg->size()); });

					if (!PinCallback)
						throw Pkcs11Exception (CKR_USER_NOT_LOGGED_IN);
					(*PinCallback) (pin);
					if (pin.find ('\0') != string::npos || pin.size() > (numeric_limits<CK_ULONG>::max)())
						throw Pkcs11Exception (CKR_PIN_LEN_RANGE);
					Login(slotId, pin.c_str());
				}

				Sessions[slotId].UserLoggedIn = true;
			}
			catch (Pkcs11Exception& e)
			{
				CK_RV error = e.GetErrorCode();

				if (error == CKR_USER_ALREADY_LOGGED_IN)
				{
					Sessions[slotId].UserLoggedIn = true;
					break;
				}
				else if (error == CKR_PIN_INCORRECT && !(tokenInfo.Flags & CKF_PROTECTED_AUTHENTICATION_PATH))
				{
					PinCallback->notifyIncorrectPin();
					if (WarningCallback)
						(*WarningCallback) (Pkcs11Exception(CKR_PIN_INCORRECT));
					continue;
				}

				throw;
			}
		}
	}

#ifdef TC_WINDOWS
	void SecurityTokenImpl::InitLibrary (const wstring &pkcs11LibraryPath, shared_ptr <GetPinFunctor> pinCallback, shared_ptr <SendExceptionFunctor> warningCallback)
#else
	void SecurityTokenImpl::InitLibrary (const string &pkcs11LibraryPath, shared_ptr <GetPinFunctor> pinCallback, shared_ptr <SendExceptionFunctor> warningCallback)
#endif
	{
		if (Initialized)
			CloseLibrary();

#ifdef TC_WINDOWS
		Pkcs11LibraryHandle = LoadLibraryW(pkcs11LibraryPath.c_str());
		throw_sys_if(!Pkcs11LibraryHandle);
#else
		Pkcs11LibraryHandle = dlopen(pkcs11LibraryPath.c_str(), RTLD_NOW | RTLD_LOCAL);
		throw_sys_sub_if(!Pkcs11LibraryHandle, dlerror());
#endif

		try
		{
			typedef CK_RV(*C_GetFunctionList_t) (CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
#ifdef TC_WINDOWS
			C_GetFunctionList_t C_GetFunctionList = (C_GetFunctionList_t) GetProcAddress (Pkcs11LibraryHandle, "C_GetFunctionList");
#else
			C_GetFunctionList_t C_GetFunctionList = (C_GetFunctionList_t) dlsym (Pkcs11LibraryHandle, "C_GetFunctionList");
#endif
			if (!C_GetFunctionList)
				throw SecurityTokenLibraryNotInitialized();
			CK_RV status = C_GetFunctionList (&Pkcs11Functions);
			if (status != CKR_OK)
				throw Pkcs11Exception (status);
			if (!Pkcs11Functions)
				throw SecurityTokenLibraryNotInitialized();
			status = Pkcs11Functions->C_Initialize (NULL_PTR);
			if (status != CKR_OK)
				throw Pkcs11Exception (status);
		}
		catch (...)
		{
#ifdef TC_WINDOWS
			FreeLibrary (Pkcs11LibraryHandle);
#else
			dlclose (Pkcs11LibraryHandle);
#endif
			Pkcs11LibraryHandle = nullptr;
			Pkcs11Functions = NULL_PTR;
			throw;
		}

		PinCallback = pinCallback;
		WarningCallback = warningCallback;

		Initialized = true;
	}

	void SecurityTokenImpl::OpenSession (CK_SLOT_ID slotId)
	{
		if (Sessions.find(slotId) != Sessions.end())
			return;

		CK_SESSION_HANDLE session;

		CK_FLAGS flags = CKF_SERIAL_SESSION;

		if (!(GetTokenInfo(slotId).Flags & CKF_WRITE_PROTECTED))
			flags |= CKF_RW_SESSION;

		CK_RV status = Pkcs11Functions->C_OpenSession(slotId, flags, NULL_PTR, NULL_PTR, &session);
		if (status != CKR_OK)
			throw Pkcs11Exception(status);

		Sessions[slotId].Handle = session;
		Sessions[slotId].Generation = ++NextSessionGeneration;
	}

	void SecurityTokenImpl::GetObjectAttribute (SecurityTokenScheme &key, CK_ATTRIBUTE_TYPE attributeType, vector <uint8> &attributeValue) {
		return GetObjectAttribute(key.SlotId, key.Handle, attributeType, attributeValue);
	}

	Pkcs11Exception::operator string () const
	{
		if (ErrorCode == CKR_OK)
			return string();

		static const struct
		{
			CK_RV ErrorCode;
			const char* ErrorString;
		} ErrorStrings[] =
		{
#			define TC_TOKEN_ERR(CODE) { CODE, #CODE },

			TC_TOKEN_ERR(CKR_CANCEL)
			TC_TOKEN_ERR(CKR_HOST_MEMORY)
			TC_TOKEN_ERR(CKR_SLOT_ID_INVALID)
			TC_TOKEN_ERR(CKR_GENERAL_ERROR)
			TC_TOKEN_ERR(CKR_FUNCTION_FAILED)
			TC_TOKEN_ERR(CKR_ARGUMENTS_BAD)
			TC_TOKEN_ERR(CKR_NO_EVENT)
			TC_TOKEN_ERR(CKR_NEED_TO_CREATE_THREADS)
			TC_TOKEN_ERR(CKR_CANT_LOCK)
			TC_TOKEN_ERR(CKR_ATTRIBUTE_READ_ONLY)
			TC_TOKEN_ERR(CKR_ATTRIBUTE_SENSITIVE)
			TC_TOKEN_ERR(CKR_ATTRIBUTE_TYPE_INVALID)
			TC_TOKEN_ERR(CKR_ATTRIBUTE_VALUE_INVALID)
			TC_TOKEN_ERR(CKR_DATA_INVALID)
			TC_TOKEN_ERR(CKR_DATA_LEN_RANGE)
			TC_TOKEN_ERR(CKR_DEVICE_ERROR)
			TC_TOKEN_ERR(CKR_DEVICE_MEMORY)
			TC_TOKEN_ERR(CKR_DEVICE_REMOVED)
			TC_TOKEN_ERR(CKR_ENCRYPTED_DATA_INVALID)
			TC_TOKEN_ERR(CKR_ENCRYPTED_DATA_LEN_RANGE)
			TC_TOKEN_ERR(CKR_FUNCTION_CANCELED)
			TC_TOKEN_ERR(CKR_FUNCTION_NOT_PARALLEL)
			TC_TOKEN_ERR(CKR_FUNCTION_NOT_SUPPORTED)
			TC_TOKEN_ERR(CKR_KEY_HANDLE_INVALID)
			TC_TOKEN_ERR(CKR_KEY_SIZE_RANGE)
			TC_TOKEN_ERR(CKR_KEY_TYPE_INCONSISTENT)
			TC_TOKEN_ERR(CKR_KEY_NOT_NEEDED)
			TC_TOKEN_ERR(CKR_KEY_CHANGED)
			TC_TOKEN_ERR(CKR_KEY_NEEDED)
			TC_TOKEN_ERR(CKR_KEY_INDIGESTIBLE)
			TC_TOKEN_ERR(CKR_KEY_FUNCTION_NOT_PERMITTED)
			TC_TOKEN_ERR(CKR_KEY_NOT_WRAPPABLE)
			TC_TOKEN_ERR(CKR_KEY_UNEXTRACTABLE)
			TC_TOKEN_ERR(CKR_MECHANISM_INVALID)
			TC_TOKEN_ERR(CKR_MECHANISM_PARAM_INVALID)
			TC_TOKEN_ERR(CKR_OBJECT_HANDLE_INVALID)
			TC_TOKEN_ERR(CKR_OPERATION_ACTIVE)
			TC_TOKEN_ERR(CKR_OPERATION_NOT_INITIALIZED)
			TC_TOKEN_ERR(CKR_PIN_INCORRECT)
			TC_TOKEN_ERR(CKR_PIN_INVALID)
			TC_TOKEN_ERR(CKR_PIN_LEN_RANGE)
			TC_TOKEN_ERR(CKR_PIN_EXPIRED)
			TC_TOKEN_ERR(CKR_PIN_LOCKED)
			TC_TOKEN_ERR(CKR_SESSION_CLOSED)
			TC_TOKEN_ERR(CKR_SESSION_COUNT)
			TC_TOKEN_ERR(CKR_SESSION_HANDLE_INVALID)
			TC_TOKEN_ERR(CKR_SESSION_PARALLEL_NOT_SUPPORTED)
			TC_TOKEN_ERR(CKR_SESSION_READ_ONLY)
			TC_TOKEN_ERR(CKR_SESSION_EXISTS)
			TC_TOKEN_ERR(CKR_SESSION_READ_ONLY_EXISTS)
			TC_TOKEN_ERR(CKR_SESSION_READ_WRITE_SO_EXISTS)
			TC_TOKEN_ERR(CKR_SIGNATURE_INVALID)
			TC_TOKEN_ERR(CKR_SIGNATURE_LEN_RANGE)
			TC_TOKEN_ERR(CKR_TEMPLATE_INCOMPLETE)
			TC_TOKEN_ERR(CKR_TEMPLATE_INCONSISTENT)
			TC_TOKEN_ERR(CKR_TOKEN_NOT_PRESENT)
			TC_TOKEN_ERR(CKR_TOKEN_NOT_RECOGNIZED)
			TC_TOKEN_ERR(CKR_TOKEN_WRITE_PROTECTED)
			TC_TOKEN_ERR(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
			TC_TOKEN_ERR(CKR_UNWRAPPING_KEY_SIZE_RANGE)
			TC_TOKEN_ERR(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
			TC_TOKEN_ERR(CKR_USER_ALREADY_LOGGED_IN)
			TC_TOKEN_ERR(CKR_USER_NOT_LOGGED_IN)
			TC_TOKEN_ERR(CKR_USER_PIN_NOT_INITIALIZED)
			TC_TOKEN_ERR(CKR_USER_TYPE_INVALID)
			TC_TOKEN_ERR(CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
			TC_TOKEN_ERR(CKR_USER_TOO_MANY_TYPES)
			TC_TOKEN_ERR(CKR_WRAPPED_KEY_INVALID)
			TC_TOKEN_ERR(CKR_WRAPPED_KEY_LEN_RANGE)
			TC_TOKEN_ERR(CKR_WRAPPING_KEY_HANDLE_INVALID)
			TC_TOKEN_ERR(CKR_WRAPPING_KEY_SIZE_RANGE)
			TC_TOKEN_ERR(CKR_WRAPPING_KEY_TYPE_INCONSISTENT)
			TC_TOKEN_ERR(CKR_RANDOM_SEED_NOT_SUPPORTED)
			TC_TOKEN_ERR(CKR_RANDOM_NO_RNG)
			TC_TOKEN_ERR(CKR_DOMAIN_PARAMS_INVALID)
			TC_TOKEN_ERR(CKR_BUFFER_TOO_SMALL)
			TC_TOKEN_ERR(CKR_SAVED_STATE_INVALID)
			TC_TOKEN_ERR(CKR_INFORMATION_SENSITIVE)
			TC_TOKEN_ERR(CKR_STATE_UNSAVEABLE)
			TC_TOKEN_ERR(CKR_CRYPTOKI_NOT_INITIALIZED)
			TC_TOKEN_ERR(CKR_CRYPTOKI_ALREADY_INITIALIZED)
			TC_TOKEN_ERR(CKR_MUTEX_BAD)
			TC_TOKEN_ERR(CKR_MUTEX_NOT_LOCKED)
			TC_TOKEN_ERR(CKR_NEW_PIN_MODE)
			TC_TOKEN_ERR(CKR_NEXT_OTP)
			TC_TOKEN_ERR(CKR_FUNCTION_REJECTED)

#undef		TC_TOKEN_ERR
		};


		for (size_t i = 0; i < array_capacity(ErrorStrings); ++i)
		{
			if (ErrorStrings[i].ErrorCode == ErrorCode)
				return ErrorStrings[i].ErrorString;
		}

		stringstream s;
		s << "0x" << hex << ErrorCode;
		return s.str();

	}

#ifdef TC_HEADER_Common_Exception
	void Pkcs11Exception::Show(HWND parent) const
	{
		string errorString = string(*this);

		if (!errorString.empty())
		{
			wstringstream subjectErrorCode;
			if (SubjectErrorCodeValid)
				subjectErrorCode << L": " << SubjectErrorCode;

			if (!GetDictionaryValue(errorString.c_str()))
			{
				if (errorString.find("CKR_") == 0)
				{
					errorString = errorString.substr(4);
					for (size_t i = 0; i < errorString.size(); ++i)
					{
						if (errorString[i] == '_')
							errorString[i] = ' ';
					}
				}
				wchar_t err[8192];
				StringCbPrintfW(err, sizeof(err), L"%s:\n\n%hs%s", GetString("SECURITY_TOKEN_ERROR"), errorString.c_str(), subjectErrorCode.str().c_str());
				ErrorDirect(err, parent);
			}
			else
			{
				wstring err = GetString(errorString.c_str());

				if (SubjectErrorCodeValid)
					err += L"\n\nError code" + subjectErrorCode.str();

				ErrorDirect(err.c_str(), parent);
			}
		}
	}
#endif // TC_HEADER_Common_Exception

	shared_ptr<SecurityTokenIface> SecurityToken::impl (new SecurityTokenImpl());

#ifdef TC_HEADER_Platform_Exception

	void Pkcs11Exception::DeserializeData(shared_ptr <Stream> stream)
	{
		Exception::DeserializeData(stream);
		Serializer sr(stream);
		uint64 code;
		sr.Deserialize("ErrorCode", code);
		sr.Deserialize("SubjectErrorCodeValid", SubjectErrorCodeValid);
		sr.Deserialize("SubjectErrorCode", SubjectErrorCode);
		ErrorCode = (CK_RV)code;
	}

	void Pkcs11Exception::SerializeData(shared_ptr <Stream> stream) const
	{
		Exception::SerializeData(stream);
		Serializer sr(stream);
		sr.Serialize("ErrorCode", (uint64)ErrorCode);
		sr.Serialize("SubjectErrorCodeValid", SubjectErrorCodeValid);
		sr.Serialize("SubjectErrorCode", SubjectErrorCode);
	}

#	define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#	undef TC_EXCEPTION_NODECL
#	define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET(SecurityTokenException);

#endif
}
