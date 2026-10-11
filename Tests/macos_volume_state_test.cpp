// Check production discovery policy without creating mounts or native windows.
#include "Core/Unix/MountedFilesystem.h"
#include "Main/VolumeSnapshot.h"
#include <iostream>

using namespace VeraCrypt;

static void Require (bool condition, const char *message)
{
	if (!condition) throw std::runtime_error (message);
}

int main ()
{
	try
	{
		VolumeSnapshotState state;
		using Clock = VolumeSnapshotState::Clock;
		using std::chrono::seconds;
		const Clock::time_point start = Clock::now();
		Require (!state.HasSample() && !state.CanConfirmEmpty (true, start), "initial empty list was authoritative");
		state.RecordSample (start, true);
		Require (state.CanConfirmEmpty (true, start + seconds (1)), "fresh complete empty list ignored");
		Require (!state.CanConfirmEmpty (false, start + seconds (1)), "nonempty list allowed auto-close");
		Require (!state.IsFresh (start + seconds (8)) && !state.CanConfirmEmpty (true, start + seconds (8)), "stale empty list allowed auto-close");
		state.RecordSample (start + seconds (8), true);
		state.Invalidate();
		Require (state.HasSample() && !state.IsFresh (start + seconds (9)) && !state.IsComplete(), "invalidated display sample remained authoritative");
		state.RecordSample (start + seconds (10), false);
		Require (state.IsFresh (start + seconds (11)) && !state.CanConfirmEmpty (true, start + seconds (11)), "partial inventory treated as complete absence");
		state.RecordSample (start + seconds (12), true);
		Require (state.HasSample() && !state.CanConfirmEmpty (true, start + seconds (18)), "slow result allowed auto-close");

		MountedFilesystem mount;
		const string prefix = ".veracrypt_aux_mnt";
		mount.MountPoint = "/private/tmp/.veracrypt_aux_mnt-unit";
		mount.Owner = 501;
		for (const char *type : { "smbfs", "nfs", "macfuse", "osxfuse", "fusefs" })
		{
			mount.Type = type;
			Require (mount.IsAuxiliaryMountCandidate (prefix, 501, 501), "supported auxiliary backend ignored");
		}
		mount.Type = "apfs";
		Require (!mount.IsAuxiliaryMountCandidate (prefix, 501, 501), "unrelated filesystem entered discovery");
		mount.Type = "smbfs";
		mount.MountPoint = "/private/tmp/.veracrypt_aux_mnt-parent/ordinary";
		Require (!mount.IsAuxiliaryMountCandidate (prefix, 501, 501), "parent path qualified as auxiliary mount");
		mount.MountPoint = "/private/tmp/ordinary.veracrypt_aux_mnt";
		Require (!mount.IsAuxiliaryMountCandidate (prefix, 501, 501), "substring qualified as auxiliary basename");
		mount.MountPoint = "/private/tmp/.veracrypt_aux_mnt-unit";
		mount.Owner = 502;
		Require (!mount.IsAuxiliaryMountCandidate (prefix, 501, 502), "another user's mount entered discovery");
		Require (mount.IsAuxiliaryMountCandidate (prefix, 0, 502), "elevated caller lost original user's mount");
		Require (!mount.IsAuxiliaryMountCandidate (prefix, 0, 501), "root included unrelated user's mount");
		mount.Owner = 0;
		Require (mount.IsAuxiliaryMountCandidate (prefix, 501, 501), "root-owned auxiliary mount ignored");
		std::cout << "PASS: startup/partial/stale snapshot policy, auxiliary basename/backend/owner scope\n";
	}
	catch (std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
	return 0;
}
