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
#include "Volume/EncryptionModeXTS.h"
#ifdef WOLFCRYPT_BACKEND
#include "Volume/EncryptionModeWolfCryptXTS.h"
#endif
#include "Main/GraphicUserInterface.h"
#include "BenchmarkDialog.h"

namespace VeraCrypt
{
	BenchmarkDialog::BenchmarkDialog (wxWindow *parent)
		: BenchmarkDialogBase (parent)
	{
		BenchmarkNoteStaticText->SetLabel (LangString["IDT_BOX_BENCHMARK_INFO"]);
		BenchmarkNoteStaticText->Wrap (RightSizer->GetSize().GetWidth());

		list <size_t> bufferSizes;
		bufferSizes.push_back (1 * BYTES_PER_MB);
		bufferSizes.push_back (5 * BYTES_PER_MB);
		bufferSizes.push_back (10 * BYTES_PER_MB);
		bufferSizes.push_back (50 * BYTES_PER_MB);
		bufferSizes.push_back (100 * BYTES_PER_MB);
		bufferSizes.push_back (200 * BYTES_PER_MB);
		bufferSizes.push_back (500 * BYTES_PER_MB);
		bufferSizes.push_back (1 * BYTES_PER_GB);

		foreach (size_t size, bufferSizes)
		{
			BufferSizeChoice->Append (Gui->SizeToString (size), (void *) size);
		}

		BenchmarkChoice->Select (0);
		BufferSizeChoice->Select (1);
		
		UpdateBenchmarkList ();

		VolumePimText->SetMinSize (wxSize (Gui->GetCharWidth (VolumePimText) * 15, -1));

		wxTextValidator validator (wxFILTER_DIGITS);
		VolumePimText->SetValidator (validator);

		Layout();
		Fit();
		Center();
	}
	
	void BenchmarkDialog::UpdateBenchmarkList ()
	{
		int index = BenchmarkChoice->GetSelection ();
		if (index == 1)
		{
			// PRF case
			m_volumePimLabel->Show ();
			VolumePimText->Show ();
			
			BufferSizeChoice->Hide ();
			m_bufferSizeLabel->Hide ();
		}
		else
		{
			m_volumePimLabel->Hide ();
			VolumePimText->Hide ();
			
			BufferSizeChoice->Show ();
			m_bufferSizeLabel->Show ();
		}
		
		BenchmarkListCtrl->DeleteAllItems();
		BenchmarkListCtrl->DeleteAllColumns();
		
		if (index == 0)
		{
			// encryption case
			list <int> colPermilles;
			BenchmarkListCtrl->InsertColumn (ColumnAlgorithm, LangString["ALGORITHM"], wxLIST_FORMAT_LEFT, 1);
			colPermilles.push_back (322);

			BenchmarkListCtrl->InsertColumn (ColumnEncryption, LangString["ENCRYPTION"], wxLIST_FORMAT_RIGHT, 1);
			colPermilles.push_back (226);

			BenchmarkListCtrl->InsertColumn (ColumnDecryption, LangString["DECRYPTION"], wxLIST_FORMAT_RIGHT, 1);
			colPermilles.push_back (226);

			BenchmarkListCtrl->InsertColumn (ColumnMean, LangString["MEAN"], wxLIST_FORMAT_RIGHT, 1);
			colPermilles.push_back (226);
			
			Gui->SetListCtrlWidth (BenchmarkListCtrl, 62, false);
			Gui->SetListCtrlHeight (BenchmarkListCtrl, 14);
			Gui->SetListCtrlColumnWidths (BenchmarkListCtrl, colPermilles);
		}
		else if (index == 1)
		{
			// PRF case
			list <int> colPermilles;
			BenchmarkListCtrl->InsertColumn (ColumnAlgorithm, LangString["ALGORITHM"], wxLIST_FORMAT_LEFT, 1);
			colPermilles.push_back (322);

			BenchmarkListCtrl->InsertColumn (ColumnTime, LangString["TIME"], wxLIST_FORMAT_RIGHT, 1);
			colPermilles.push_back (226);

			BenchmarkListCtrl->InsertColumn (ColumnIterations, LangString["ITERATIONS"], wxLIST_FORMAT_RIGHT, 1);
			colPermilles.push_back (226);
			
			Gui->SetListCtrlWidth (BenchmarkListCtrl, 62, false);
			Gui->SetListCtrlHeight (BenchmarkListCtrl, 14);
			Gui->SetListCtrlColumnWidths (BenchmarkListCtrl, colPermilles);
		}
		else
		{
			// Hash case
			list <int> colPermilles;
			BenchmarkListCtrl->InsertColumn (ColumnAlgorithm, LangString["ALGORITHM"], wxLIST_FORMAT_LEFT, 1);
			colPermilles.push_back (322);

			BenchmarkListCtrl->InsertColumn (ColumnEncryption, LangString["MEAN"], wxLIST_FORMAT_RIGHT, 1);
			colPermilles.push_back (226);
			
			Gui->SetListCtrlWidth (BenchmarkListCtrl, 62, false);
			Gui->SetListCtrlHeight (BenchmarkListCtrl, 14);
			Gui->SetListCtrlColumnWidths (BenchmarkListCtrl, colPermilles);
		}
	}
	
	void BenchmarkDialog::OnBenchmarkChoiceSelected (wxCommandEvent& event)
	{
		UpdateBenchmarkList ();
		
		Layout();
		Fit();
	}

	void BenchmarkDialog::OnBenchmarkButtonClick (wxCommandEvent& event)
	{
		list <BenchmarkResult> results;

		wxBusyCursor busy;
		int opIndex = BenchmarkChoice->GetSelection ();
		Buffer buffer ((opIndex == 1)? sizeof (unsigned long) : (size_t) Gui->GetSelectedData <size_t> (BufferSizeChoice));
		
		if (opIndex == 1)
		{
			unsigned long pim = 0;
			if (!VolumePimText->GetValue().ToULong (&pim))
				pim = 0;
				
			memcpy (buffer.Ptr (), &pim, sizeof (unsigned long));
		}
		

		BenchmarkThreadRoutine routine(this, results, buffer, opIndex);
		Gui->ExecuteWaitThreadRoutine (this, &routine);

		BenchmarkListCtrl->DeleteAllItems();

		foreach (const BenchmarkResult &result, results)
		{
			vector <wstring> fields (BenchmarkListCtrl->GetColumnCount());

			fields[ColumnAlgorithm] = result.AlgorithmName;
			if (opIndex == 0)
			{
				fields[ColumnEncryption] = Gui->SpeedToString (result.EncryptionSpeed);
				fields[ColumnDecryption] = Gui->SpeedToString (result.DecryptionSpeed);
				fields[ColumnMean] = Gui->SpeedToString (result.MeanSpeed);
			}
			else if (opIndex == 1)
			{
				fields[ColumnTime] = wxString::Format (wxT("%llu ms"), (unsigned long long) result.Time);
				fields[ColumnIterations] = wxString::Format (wxT("%llu"), (unsigned long long) result.Iterations);
			}
			else
			{
				fields[ColumnHashMean] = Gui->SpeedToString (result.MeanSpeed);
			}

			Gui->AppendToListCtrl (BenchmarkListCtrl, fields);
		}

		BenchmarkListCtrl->SetColumnWidth(0, wxLIST_AUTOSIZE);
		wxSize minSize = BenchmarkListCtrl->GetBestSize ();
		minSize.IncBy (10, 20);
		BenchmarkListCtrl->SetMinSize(minSize);
		Layout ();
		Fit();
	}

	void BenchmarkDialog::DoBenchmark (list<BenchmarkResult>& results, Buffer& buffer, int opIndex)
	{
		try
		{
			if (opIndex == 0)
			{
				EncryptionAlgorithmList encryptionAlgorithms = EncryptionAlgorithm::GetAvailableAlgorithms();
				foreach (shared_ptr <EncryptionAlgorithm> ea, encryptionAlgorithms)
				{
					if (!ea->IsDeprecated())
					{
						BenchmarkResult result;
						result.AlgorithmName = ea->GetName(true);

						Buffer key (ea->GetKeySize());
						ea->SetKey (key);
                                            #ifdef WOLFCRYPT_BACKEND
						shared_ptr <EncryptionMode> xts (new EncryptionModeWolfCryptXTS);
						ea->SetKeyXTS (key);
                                            #else
						shared_ptr <EncryptionMode> xts (new EncryptionModeXTS);
                                            #endif
                                                xts->SetKey (key);
						ea->SetMode (xts);

						wxLongLong startTime = wxGetLocalTimeMillis();

						// CPU "warm up" (an attempt to prevent skewed results on systems where CPU frequency gradually changes depending on CPU load).
						do
						{
							ea->EncryptSectors (buffer, 0, buffer.Size() / ENCRYPTION_DATA_UNIT_SIZE, ENCRYPTION_DATA_UNIT_SIZE);
						}
						while (wxGetLocalTimeMillis().GetValue() - startTime.GetValue() < 20);

						uint64 size = 0;
						uint64 time;
						startTime = wxGetLocalTimeMillis();

						do
						{
							ea->EncryptSectors (buffer, 0, buffer.Size() / ENCRYPTION_DATA_UNIT_SIZE, ENCRYPTION_DATA_UNIT_SIZE);
							size += buffer.Size();
							time = (uint64) (wxGetLocalTimeMillis().GetValue() - startTime.GetValue());
						}
						while (time < 100);

						result.EncryptionSpeed = size * 1000 / time;

						startTime = wxGetLocalTimeMillis();
						size = 0;

						do
						{
							ea->DecryptSectors (buffer, 0, buffer.Size() / ENCRYPTION_DATA_UNIT_SIZE, ENCRYPTION_DATA_UNIT_SIZE);
							size += buffer.Size();
							time = (uint64) (wxGetLocalTimeMillis().GetValue() - startTime.GetValue());
						}
						while (time < 100);

						result.DecryptionSpeed = size * 1000 / time;
						result.MeanSpeed = (result.EncryptionSpeed + result.DecryptionSpeed) / 2;

						bool inserted = false;
						for (list <BenchmarkResult>::iterator i = results.begin(); i != results.end(); ++i)
						{
							if (i->MeanSpeed < result.MeanSpeed)
							{
								results.insert (i, result);
								inserted = true;
								break;
							}
						}

						if (!inserted)
							results.push_back (result);
					}
				}
			}
			else if (opIndex == 1)
			{
				Buffer dk(MASTER_KEYDATA_SIZE);
				Buffer salt(64);
				const char *tmp_salt = {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"};
				unsigned long pim;
				Pkcs5KdfList prfList = Pkcs5Kdf::GetAvailableAlgorithms ();
				VolumePassword password ((const uint8*) "passphrase-1234567890", 21);

				memcpy (&pim, buffer.Ptr (), sizeof (unsigned long));
				memcpy (salt.Ptr(), tmp_salt, 64);
				
				foreach (shared_ptr <Pkcs5Kdf> prf, prfList)
				{
					if (!prf->IsDeprecated())
					{
						BenchmarkResult result;
						result.AlgorithmName = prf->GetName ();
						result.Iterations = (uint64) prf->GetIterationCount (pim);

						uint64 time;
						wxLongLong startTime = wxGetLocalTimeMillis();
						
						for (int i = 1; i <= 2; i++) 
						{
							prf->DeriveKey (dk, password, pim, salt);
						}
						
						time = (uint64) (wxGetLocalTimeMillis().GetValue() - startTime.GetValue());

						result.Time = time / 2;
				
						bool inserted = false;
						for (list <BenchmarkResult>::iterator i = results.begin(); i != results.end(); ++i)
						{
							if (i->Time > result.Time)
							{
								results.insert (i, result);
								inserted = true;
								break;
							}
						}

						if (!inserted)
							results.push_back (result);							
					}
				}
				
			}
			else
			{
				Buffer digest (1024);
				HashList hashAlgorithms = Hash::GetAvailableAlgorithms ();
				foreach (shared_ptr <Hash> hash, hashAlgorithms)
				{
					if (!hash->IsDeprecated())
					{
						BenchmarkResult result;
						result.AlgorithmName = hash->GetName ();
						
						uint64 size = 0;
						uint64 time;
						wxLongLong startTime = wxGetLocalTimeMillis();
						
						// CPU "warm up" (an attempt to prevent skewed results on systems where CPU frequency gradually changes depending on CPU load).
						do
						{
							hash->Init ();
							hash->ProcessData (digest);
							hash->GetDigest (digest);
						}
						while (wxGetLocalTimeMillis().GetValue() - startTime.GetValue() < 100);


						startTime = wxGetLocalTimeMillis();
						do
						{
							hash->Init ();
							hash->ProcessData (buffer);
							hash->GetDigest (digest);
							time = (uint64) (wxGetLocalTimeMillis().GetValue() - startTime.GetValue());
							size += buffer.Size ();
						}
						while (time < 2000);

						result.MeanSpeed = size * 1000 / time;

						bool inserted = false;
						for (list <BenchmarkResult>::iterator i = results.begin(); i != results.end(); ++i)
						{
							if (i->MeanSpeed < result.MeanSpeed)
							{
								results.insert (i, result);
								inserted = true;
								break;
							}
						}

						if (!inserted)
							results.push_back (result);
						
					}
				}
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}
}
