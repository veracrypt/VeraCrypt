ARM64 VeraCrypt-DCS staging directory
=====================================

The release EFI resources in this directory are versioned, as are the
existing x64 DCS resources, so a clean VeraCrypt checkout can build Setup
without an unrecorded staging dependency.

Regenerate them from the companion VeraCrypt-DCS repository with:

  Dcs_bld.bat ARM64Rel VS2022

Then stage and validate the AArch64 outputs before building VeraCrypt:

  powershell -ExecutionPolicy Bypass -File Stage-Dcs.ps1 `
    -BuildOutput C:\path\to\VeraCrypt-DCS\Build\DcsPkg\RELEASE_VS2022\AARCH64

The staging script rejects missing, malformed, or non-AArch64 PE images and
prints the SHA-256 hash of every staged resource. Commit all seven refreshed
resources together with the source revisions that produced them.
