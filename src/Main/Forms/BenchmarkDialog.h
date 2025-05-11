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

#ifndef TC_HEADER_Main_Forms_BenchmarkDialog
#define TC_HEADER_Main_Forms_BenchmarkDialog

#include "Forms.h"
#include "Main/Main.h"

namespace VeraCrypt
{
	class BenchmarkDialog : public BenchmarkDialogBase
	{
	public:
		BenchmarkDialog (wxWindow *parent);

	protected:
		enum
		{
			ColumnAlgorithm = 0,
			ColumnEncryption,
			ColumnDecryption,
			ColumnMean,
			ColumnTime = 1,
			ColumnIterations = 2,
			ColumnHashMean = 1			
		};

		struct BenchmarkResult
		{
			wstring AlgorithmName;
			uint64 EncryptionSpeed;
			uint64 DecryptionSpeed;
			uint64 MeanSpeed;
			uint64 Time;
			uint64 Iterations;
		};

		void UpdateBenchmarkList ();
		void DoBenchmark (list<BenchmarkResult>& results, Buffer& buffer, int opIndex);
		void OnBenchmarkChoiceSelected (wxCommandEvent& event);
		void OnBenchmarkButtonClick (wxCommandEvent& event);

		class BenchmarkThreadRoutine : public WaitThreadRoutine
		{
		public:
			BenchmarkDialog* m_pDlg;
			list<BenchmarkResult>& m_results;
			Buffer& m_buffer;
			int m_opIndex;
			BenchmarkThreadRoutine(BenchmarkDialog* pDlg, list<BenchmarkResult>& results, Buffer& buffer, int opIndex)
				: m_pDlg(pDlg), m_results(results), m_buffer(buffer), m_opIndex (opIndex) { }
			virtual ~BenchmarkThreadRoutine() { }
			virtual void ExecutionCode(void) { m_pDlg->DoBenchmark (m_results, m_buffer, m_opIndex); }
		};
	};
}

#endif // TC_HEADER_Main_Forms_BenchmarkDialog
