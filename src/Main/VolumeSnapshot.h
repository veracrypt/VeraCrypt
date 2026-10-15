/*
 Copyright (c) 2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0, included in License.txt.
*/

// Local GUI discovery state. Kept independent of wxWidgets so lifecycle
// decisions can be checked without a native event loop or mounted volumes.
#ifndef TC_HEADER_Main_VolumeSnapshot
#define TC_HEADER_Main_VolumeSnapshot

#include <chrono>

namespace VeraCrypt
{
	class VolumeSnapshotState
	{
	public:
		using Clock = std::chrono::steady_clock;
		VolumeSnapshotState () : Available (false), Current (false), Complete (false) { }

		// Staleness only suspends decisions. Activity counters are cumulative per
		// volume instance, so observation gaps do not invalidate idle tracking.
		void RecordSample (Clock::time_point sampledAt, bool complete)
		{
			Available = Current = true;
			Complete = complete;
			SampledAt = sampledAt;
		}
		void Invalidate () { Current = false; }
		bool HasSample () const { return Available; }
		bool IsComplete () const { return Current && Complete; }
		bool IsFresh (Clock::time_point now = Clock::now()) const
		{
			return Current && Available && now - SampledAt < std::chrono::seconds (6);
		}
		bool CanConfirmEmpty (bool empty, Clock::time_point now = Clock::now()) const
		{
			return empty && IsComplete() && IsFresh (now);
		}

	private:
		bool Available, Current, Complete;
		Clock::time_point SampledAt;
	};
}

#endif
