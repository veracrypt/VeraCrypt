/*
 Copyright (c) 2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
			ColumnMean
		};

		struct BenchmarkResult
		{
			wstring AlgorithmName;
			uint64 EncryptionSpeed;
			uint64 DecryptionSpeed;
			uint64 MeanSpeed;
		};

		void DoBenchmark (list<BenchmarkResult>& results, Buffer& buffer);
		void OnBenchmarkButtonClick (wxCommandEvent& event);
		
		class BenchmarkThreadRoutine : public WaitThreadRoutine
		{
		public:
			BenchmarkDialog* m_pDlg;
			list<BenchmarkResult>& m_results;
			Buffer& m_buffer;
			BenchmarkThreadRoutine(BenchmarkDialog* pDlg, list<BenchmarkResult>& results, Buffer& buffer)
				: m_pDlg(pDlg), m_results(results), m_buffer(buffer) { }
			virtual ~BenchmarkThreadRoutine() { }
			virtual void ExecutionCode(void) { m_pDlg->DoBenchmark (m_results, m_buffer); }
		};
	};
}

#endif // TC_HEADER_Main_Forms_BenchmarkDialog
