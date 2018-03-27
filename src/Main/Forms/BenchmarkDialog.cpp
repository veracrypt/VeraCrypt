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

#include "System.h"
#include "Volume/EncryptionModeXTS.h"
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

		BufferSizeChoice->Select (1);

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

		Layout();
		Fit();
		Center();
	}

	void BenchmarkDialog::OnBenchmarkButtonClick (wxCommandEvent& event)
	{
		list <BenchmarkResult> results;

		wxBusyCursor busy;
		Buffer buffer ((size_t) Gui->GetSelectedData <size_t> (BufferSizeChoice));

		BenchmarkThreadRoutine routine(this, results, buffer);
		Gui->ExecuteWaitThreadRoutine (this, &routine);

		BenchmarkListCtrl->DeleteAllItems();

		foreach (const BenchmarkResult &result, results)
		{
			vector <wstring> fields (BenchmarkListCtrl->GetColumnCount());

			fields[ColumnAlgorithm] = result.AlgorithmName;
			fields[ColumnEncryption] = Gui->SpeedToString (result.EncryptionSpeed);
			fields[ColumnDecryption] = Gui->SpeedToString (result.DecryptionSpeed);
			fields[ColumnMean] = Gui->SpeedToString (result.MeanSpeed);

			Gui->AppendToListCtrl (BenchmarkListCtrl, fields);
		}

		BenchmarkListCtrl->SetColumnWidth(0, wxLIST_AUTOSIZE);
		wxSize minSize = BenchmarkListCtrl->GetBestSize ();
		minSize.IncBy (10, 20);
		BenchmarkListCtrl->SetMinSize(minSize);
		Layout ();
		Fit();
	}

	void BenchmarkDialog::DoBenchmark (list<BenchmarkResult>& results, Buffer& buffer)
	{
		try
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

					shared_ptr <EncryptionMode> xts (new EncryptionModeXTS);
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
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}
}
