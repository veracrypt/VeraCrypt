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

 #include <Platform/File.h>
 #include <Platform/FilesystemPath.h>
 #include <Volume/Crc32.h>

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

	MechanismList SecurityTokenMechanism::GetAvailableMechanisms ()
	{
		MechanismList l;

#ifdef DEBUG
		l.push_back(make_shared<RSASecurityTokenMechanism>());
#endif

		l.push_back(make_shared<RSAOAEPSecurityTokenMechanism>());

		return l;
	}

	CK_MECHANISM RSASecurityTokenMechanism::_MECHANISM = { CKM_RSA_PKCS, NULL_PTR, 0};

	bool RSASecurityTokenMechanism::ApplyTo(SecurityTokenScheme &key) {
		key.MechanismLabel = GetLabel();

		vector <uint8> attrib;
		SecurityToken::GetObjectAttribute (key, CKA_KEY_TYPE, attrib);
		if (attrib.size() == sizeof(CK_ULONG) && *(CK_ULONG *) &attrib.front() != CKK_RSA) {
			return false;
		}
		

		CK_MECHANISM_INFO mechInfo;
		if (!SecurityToken::GetMechanismInfo(key.SlotId, CKM_RSA_PKCS, &mechInfo)) {
			return false;
		}

		// CKA_MODULUS_BITS is Length in bits of modulus n
		SecurityToken::GetObjectAttribute (key, CKA_MODULUS_BITS, attrib);
		if (attrib.size() != sizeof (CK_ULONG)) {
			return false;
		}


		CK_ULONG k = *(CK_ULONG *) &attrib.front();

		if (k > mechInfo.ulMaxKeySize || k < mechInfo.ulMinKeySize) {
			return false;
		}

		// for private key (decrypt)
		// k is the length in bytes of the RSA modulus.
		key.DecryptOutputSize = k/8 - 11; // C_Encrypt input length
		key.EncryptOutputSize = k/8; // C_Encrypt output length

		key.Mechanism = &_MECHANISM;
		return true;
	}


	CK_RSA_PKCS_OAEP_PARAMS RSAOAEPSecurityTokenMechanism::_OAEP_PARAMS = {CKM_SHA256, CKG_MGF1_SHA256, 0, NULL_PTR, 0};
	CK_MECHANISM RSAOAEPSecurityTokenMechanism::_MECHANISM = {CKM_RSA_PKCS_OAEP, (void *) &_OAEP_PARAMS, sizeof(_OAEP_PARAMS)};

	bool RSAOAEPSecurityTokenMechanism::ApplyTo(SecurityTokenScheme &key) {
		key.MechanismLabel = GetLabel();

		vector <uint8> attrib;
		SecurityToken::GetObjectAttribute (key, CKA_KEY_TYPE, attrib);
		if (attrib.size() == sizeof(CK_ULONG) && *(CK_ULONG *) &attrib.front() != CKK_RSA) {
			return false;
		}

		CK_MECHANISM_INFO mechInfo;
		if (!SecurityToken::GetMechanismInfo(key.SlotId, CKM_RSA_PKCS, &mechInfo)) {
			return false;
		}

		// CKA_MODULUS_BITS is Length in bits of modulus n
		SecurityToken::GetObjectAttribute (key, CKA_MODULUS_BITS, attrib);
		if (attrib.size() != sizeof (CK_ULONG)) {
			return false;
		}

		CK_ULONG k = *(CK_ULONG *) &attrib.front();

		if (k > mechInfo.ulMaxKeySize || k < mechInfo.ulMinKeySize) {
			return false;
		}

		const int hLen = 256 / 8;

		// k is the length in bytes of the RSA modulus
		// hLen is the output length of the message digest algorithm specified by the hashAlg field of the CK_RSA_PKCS_OAEP_PARAMS structure
		key.DecryptOutputSize = k/8 - 2 - 2*hLen - _OAEP_PARAMS.ulSourceDataLen;
		key.EncryptOutputSize = k/8;
		key.Mechanism = &_MECHANISM;
		return true;
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
		}
	}

	void SecurityTokenImpl::CloseAllSessions () throw ()
	{
		if (!Initialized)
			return;

		typedef pair <CK_SLOT_ID, Pkcs11Session> SessionMapPair;

		foreach(SessionMapPair p, Sessions)
		{
			try
			{
				CloseSession(p.first);
			}
			catch (...) {}
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
		if (name.empty())
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


	void SecurityTokenImpl::GetSecurityTokenScheme(wstring tokenKeyDescriptor, SecurityTokenScheme &key, SecurityTokenKeyOperation mode)
	{

		size_t slotEnds = tokenKeyDescriptor.find(L":");
		if (slotEnds == std::string::npos) {
			throw InvalidSecurityTokenKeyfilePath();
		}

		size_t labelEnds = tokenKeyDescriptor.find(L":", slotEnds+1);
		if (labelEnds == std::string::npos) {
			throw InvalidSecurityTokenKeyfilePath();
		}

		CK_SLOT_ID slotId = StringConverter::ToUInt64(tokenKeyDescriptor.substr(0, slotEnds));
		wstring keyId = tokenKeyDescriptor.substr(slotEnds+1, labelEnds-slotEnds-1);
		wstring mechanismLabel = tokenKeyDescriptor.substr(labelEnds+1);

		vector <SecurityTokenScheme> keys;
		if (mode == SecurityTokenKeyOperation::ENCRYPT) {
		 	keys = SecurityToken::GetAvailablePublicKeys(&slotId, keyId, mechanismLabel);
		} else if (mode == SecurityTokenKeyOperation::DECRYPT) {
			keys = SecurityToken::GetAvailablePrivateKeys(&slotId, keyId, mechanismLabel);
		} else {
			throw ParameterIncorrect(SRC_POS);
		}
		if (keys.size() > 1 || keys.size() == 0) {
			throw Pkcs11Exception (CKR_KEY_NEEDED);
		}
		key = keys[0];
	}

	vector <SecurityTokenScheme> SecurityTokenImpl::GetAvailablePrivateKeys(CK_SLOT_ID *slotIdFilter, const wstring keyIdFilter, const wstring mechanismLabel)
	{
		bool unrecognizedTokenPresent = false;
		vector <SecurityTokenScheme> keys;

		auto mechanisms = SecurityTokenMechanism::GetAvailableMechanisms();

		foreach (const CK_SLOT_ID &slotId, GetTokenSlots())
		{
			SecurityTokenInfo token;

			if (slotIdFilter && *slotIdFilter != slotId)
				continue;

			try
			{
				LoginUserIfRequired (slotId);
				token = GetTokenInfo (slotId);
			}
			catch (UserAbort &)
			{
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

			foreach (const CK_OBJECT_HANDLE &dataHandle, GetObjects (slotId, CKO_PRIVATE_KEY))
			{
				SecurityTokenScheme key;
				key.Handle = dataHandle;
				key.SlotId = slotId;
				key.Token = token;

				vector <uint8> privateAttrib;
				GetObjectAttribute (slotId, dataHandle, CKA_PRIVATE, privateAttrib);

				if (privateAttrib.size() == sizeof (CK_BBOOL) && *(CK_BBOOL *) &privateAttrib.front() != CK_TRUE)
					continue;
			
				// check if CKA_DECRYPT is present
				GetObjectAttribute (slotId, dataHandle, CKA_DECRYPT, privateAttrib);
				if (privateAttrib.size() == sizeof(CK_BBOOL) && *(CK_BBOOL *) &privateAttrib.front() != CK_TRUE) {
					continue;
				}

				vector <uint8> label;
				GetObjectAttribute (slotId, dataHandle, CKA_LABEL, label);
				label.push_back (0);

				key.IdUtf8 = (char *) &label.front();

#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
				key.Id = Utf8StringToWide ((const char *) &label.front());
#else
				key.Id = StringConverter::ToWide ((const char *) &label.front());
#endif

				if (key.Id.empty() || (!keyIdFilter.empty() && keyIdFilter != key.Id)) {
					continue;
				}

				keys.push_back (key);

				if (!keyIdFilter.empty())
					break;
			}
		}

		if (keys.empty() && unrecognizedTokenPresent)
			throw Pkcs11Exception (CKR_TOKEN_NOT_RECOGNIZED);

		vector <SecurityTokenScheme> keysWithSchema;
		for (auto key = keys.begin(); key != keys.end(); ++key) {
			for (auto mechanism = mechanisms.begin(); mechanism != mechanisms.end(); ++mechanism) {
				if ((*mechanism)->ApplyTo(*key)) {
					bool mechanismMatches = mechanismLabel.empty() || mechanismLabel == key->MechanismLabel;
					if (mechanismMatches) {
						SecurityTokenScheme keyAndSchema = *key;
						keysWithSchema.push_back(keyAndSchema);
					}
				}
			}
		}

		return keysWithSchema;
	}


	vector <SecurityTokenScheme> SecurityTokenImpl::GetAvailablePublicKeys(CK_SLOT_ID *slotIdFilter, const wstring keyIdFilter, const wstring mechanismLabel)
	{
		bool unrecognizedTokenPresent = false;
		vector <SecurityTokenScheme> keys;

		auto mechanisms = SecurityTokenMechanism::GetAvailableMechanisms();

		foreach (const CK_SLOT_ID &slotId, GetTokenSlots())
		{
			SecurityTokenInfo token;

			if (slotIdFilter && *slotIdFilter != slotId)
				continue;

			try
			{
				LoginUserIfRequired (slotId);
				token = GetTokenInfo (slotId);
			}
			catch (UserAbort &)
			{
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

			foreach (const CK_OBJECT_HANDLE &dataHandle, GetObjects (slotId, CKO_PUBLIC_KEY))
			{
				SecurityTokenScheme key;
				key.Handle = dataHandle;
				key.SlotId = slotId;
				key.Token = token;

				vector <uint8> publicAttrib;
				GetObjectAttribute (slotId, dataHandle, CKA_PRIVATE, publicAttrib);
				if (publicAttrib.size() == sizeof (CK_BBOOL) && *(CK_BBOOL *) &publicAttrib.front() != CK_FALSE)
					continue;

				// check if CKA_ENCRYPT attribute present
				GetObjectAttribute (slotId, dataHandle, CKA_ENCRYPT, publicAttrib);
				if (publicAttrib.size() == sizeof (CK_BBOOL) && *(CK_BBOOL *) &publicAttrib.front() != CK_TRUE) {
					continue;
				}

				vector <uint8> label;
				GetObjectAttribute (slotId, dataHandle, CKA_LABEL, label);
				label.push_back (0);

				key.IdUtf8 = (char *) &label.front();

#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
				key.Id = Utf8StringToWide ((const char *) &label.front());
#else
				key.Id = StringConverter::ToWide ((const char *) &label.front());
#endif

				if (key.Id.empty() || (!keyIdFilter.empty() && keyIdFilter != key.Id)) {
					continue;
				}

				keys.push_back (key);

				if (!keyIdFilter.empty())
					break;
			}
		}

		if (keys.empty() && unrecognizedTokenPresent)
			throw Pkcs11Exception (CKR_TOKEN_NOT_RECOGNIZED);

		vector <SecurityTokenScheme> keysWithSchema;
		for (auto key = keys.begin(); key != keys.end(); ++key) {
			for (auto mechanism = mechanisms.begin(); mechanism != mechanisms.end(); ++mechanism) {
				if ((*mechanism)->ApplyTo(*key)) {
					bool mechanismMatches = mechanismLabel.empty() || mechanismLabel == key->MechanismLabel;
					if (mechanismMatches) {
						SecurityTokenScheme keyAndSchema = *key;
						keysWithSchema.push_back(keyAndSchema);
					}
				}
			}
		}

		return keysWithSchema;
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

			for(const CK_OBJECT_HANDLE & dataHandle: GetObjects(slotId, CKO_DATA))
			{
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
		CK_TOKEN_INFO info;
		CK_RV status = Pkcs11Functions->C_GetTokenInfo(slotId, &info);
		if (status != CKR_OK)
			throw Pkcs11Exception(status);

		SecurityTokenInfo token;
		token.SlotId = slotId;
		token.Flags = info.flags;

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


	CK_RV SecurityTokenImpl::PKCS11Encrypt(CK_SESSION_HANDLE hSession, vector<uint8> plaintext, vector<uint8> &ciphertext)
	{
		CK_RV rv;
		if (!plaintext.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG outDataLen = ciphertext.size();
		rv = Pkcs11Functions->C_Encrypt(hSession, plaintext.data(), plaintext.size(), ciphertext.data(),
			&outDataLen);

		if (CKR_OK == rv) {
			ciphertext = vector<uint8>(ciphertext.data(), ciphertext.data() + outDataLen);
		} else {
			throw Pkcs11Exception(rv);
		}
		return rv;
	}

	CK_RV SecurityTokenImpl::PKCS11Decrypt(CK_SESSION_HANDLE hSession, vector<uint8> ciphertext, vector<uint8> &plaintext)
	{
		CK_RV rv;
		if (!ciphertext.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG outDataLen;

		// get output buffer size
		rv = Pkcs11Functions->C_Decrypt(hSession, ciphertext.data(), ciphertext.size(), NULL_PTR,
			&outDataLen);
		if (CKR_OK != rv) {
			throw Pkcs11Exception(rv);
		}

		plaintext = vector<uint8>((size_t)outDataLen);
		rv = Pkcs11Functions->C_Decrypt(hSession, ciphertext.data(), ciphertext.size(), plaintext.data(),
			&outDataLen);

		if (CKR_OK == rv) {
			plaintext = vector<uint8>(plaintext.data(), plaintext.data() + outDataLen);
		} else {
			throw Pkcs11Exception(rv);
		}
		return rv;
	}

	void SecurityTokenImpl::GetEncryptedData(SecurityTokenScheme key, vector<uint8> plaintext, vector<uint8> &ciphertext) {
		ciphertext = vector<uint8>(key.EncryptOutputSize);
		GetEncryptedData(key.SlotId, key.Handle, key.Mechanism, plaintext, ciphertext);
	}

	void SecurityTokenImpl::GetEncryptedData (CK_SLOT_ID slotId, CK_OBJECT_HANDLE tokenObject, CK_MECHANISM_PTR mechanism, vector <uint8> plaintext, vector <uint8> &ciphertext)
	{
		LoginUserIfRequired (slotId);

		if (Sessions.find (slotId) == Sessions.end())
			throw ParameterIncorrect (SRC_POS);

		CK_RV status = Pkcs11Functions->C_EncryptInit (Sessions[slotId].Handle, mechanism, tokenObject);
		if (status != CKR_OK) {
			throw Pkcs11Exception (status);
		}

		status = PKCS11Encrypt(
			Sessions[slotId].Handle,
			plaintext,
			ciphertext
		);

		if (status != CKR_OK) {
			throw Pkcs11Exception (status);
		}

	}

	void SecurityTokenImpl::GetDecryptedData(SecurityTokenScheme key, vector<uint8> ciphertext, vector<uint8> &plaintext)
	{
		GetDecryptedData(key.SlotId, key.Handle, key.Mechanism, ciphertext, plaintext);
	}

	void SecurityTokenImpl::GetDecryptedData (CK_SLOT_ID slotId, CK_OBJECT_HANDLE tokenObject, CK_MECHANISM_PTR mechanism, vector <uint8> ciphertext, vector <uint8> &plaintext)
	{
		LoginUserIfRequired (slotId);

		if (Sessions.find (slotId) == Sessions.end())
			throw ParameterIncorrect (SRC_POS);

		CK_RV status = Pkcs11Functions->C_DecryptInit (Sessions[slotId].Handle, mechanism, tokenObject);
		if (status != CKR_OK) {
			throw Pkcs11Exception (status);
		}

		status = PKCS11Decrypt(
			Sessions[slotId].Handle,
			ciphertext,
			plaintext
		);

		if (status != CKR_OK) {
			throw Pkcs11Exception (status);
		}

	}

	void SecurityTokenImpl::GetObjectAttribute (CK_SLOT_ID slotId, CK_OBJECT_HANDLE tokenObject, CK_ATTRIBUTE_TYPE attributeType, vector <uint8> &attributeValue)
	{
		attributeValue.clear();

		if (Sessions.find(slotId) == Sessions.end())
			throw ParameterIncorrect(SRC_POS);

		CK_ATTRIBUTE attribute;
		attribute.type = attributeType;
		attribute.pValue = NULL_PTR;

		CK_RV status = Pkcs11Functions->C_GetAttributeValue(Sessions[slotId].Handle, tokenObject, &attribute, 1);
		if (status != CKR_OK)
			throw Pkcs11Exception(status);

		if (attribute.ulValueLen == 0)
			return;

		attributeValue = vector <uint8>(attribute.ulValueLen);
		attribute.pValue = &attributeValue.front();

		status = Pkcs11Functions->C_GetAttributeValue(Sessions[slotId].Handle, tokenObject, &attribute, 1);
		if (status != CKR_OK)
			throw Pkcs11Exception(status);
	}

	list <CK_SLOT_ID> SecurityTokenImpl::GetTokenSlots ()
	{
		CheckLibraryStatus();

		list <CK_SLOT_ID> slots;
		CK_ULONG slotCount;

		CK_RV status = Pkcs11Functions->C_GetSlotList(TRUE, NULL_PTR, &slotCount);
		if (status != CKR_OK)
			throw Pkcs11Exception(status);

		if (slotCount > 0)
		{
			vector <CK_SLOT_ID> slotArray(slotCount);
			status = Pkcs11Functions->C_GetSlotList(TRUE, &slotArray.front(), &slotCount);
			if (status != CKR_OK)
				throw Pkcs11Exception(status);

			for (size_t i = 0; i < slotCount; i++)
			{
				CK_SLOT_INFO slotInfo;
				status = Pkcs11Functions->C_GetSlotInfo(slotArray[i], &slotInfo);

				if (status != CKR_OK || !(slotInfo.flags & CKF_TOKEN_PRESENT))
					continue;

				slots.push_back(slotArray[i]);
			}
		}

		return slots;
	}

	 bool SecurityTokenImpl::GetMechanismInfo(CK_SLOT_ID slotId, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR mechanismInfo) {
		CK_MECHANISM_INFO mechInfo;
		CK_RV status = Pkcs11Functions->C_GetMechanismInfo(slotId, type, &mechInfo);
		if (status != CKR_OK) {
			return false;
		} else {
			*mechanismInfo = mechInfo;
			return true;
		}
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

		if (status != CKR_OK)
			throw Pkcs11Exception(status);

		Sessions[slotId].UserLoggedIn = true;
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

					(*PinCallback) (pin);
					Login(slotId, pin.c_str());
				}

				Sessions[slotId].UserLoggedIn = true;
			}
			catch (Pkcs11Exception& e)
			{
				CK_RV error = e.GetErrorCode();

				if (error == CKR_USER_ALREADY_LOGGED_IN)
				{
					break;
				}
				else if (error == CKR_PIN_INCORRECT && !(tokenInfo.Flags & CKF_PROTECTED_AUTHENTICATION_PATH))
				{
					PinCallback->notifyIncorrectPin();
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


		typedef CK_RV(*C_GetFunctionList_t) (CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
#ifdef TC_WINDOWS
		C_GetFunctionList_t C_GetFunctionList = (C_GetFunctionList_t)GetProcAddress(Pkcs11LibraryHandle, "C_GetFunctionList");
#else
		C_GetFunctionList_t C_GetFunctionList = (C_GetFunctionList_t)dlsym(Pkcs11LibraryHandle, "C_GetFunctionList");
#endif

		if (!C_GetFunctionList)
			throw SecurityTokenLibraryNotInitialized();

		CK_RV status = C_GetFunctionList(&Pkcs11Functions);
		if (status != CKR_OK)
			throw Pkcs11Exception(status);

		status = Pkcs11Functions->C_Initialize(NULL_PTR);
		if (status != CKR_OK)
			throw Pkcs11Exception(status);

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

	shared_ptr<SecurityTokenIface> SecurityToken::impl;

#ifdef TC_HEADER_Platform_Exception

	void Pkcs11Exception::Deserialize(shared_ptr <Stream> stream)
	{
		Exception::Deserialize(stream);
		Serializer sr(stream);
		uint64 code;
		sr.Deserialize("ErrorCode", code);
		sr.Deserialize("SubjectErrorCodeValid", SubjectErrorCodeValid);
		sr.Deserialize("SubjectErrorCode", SubjectErrorCode);
		ErrorCode = (CK_RV)code;
	}

	void Pkcs11Exception::Serialize(shared_ptr <Stream> stream) const
	{
		Exception::Serialize(stream);
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
