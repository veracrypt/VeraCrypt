The source code for VeraCrypt EFI bootloader files is available at: https://github.com/veracrypt/VeraCrypt-DCS
Use tag "VeraCrypt_1.18" to extract the sources that were used when building VeraCrypt 1.18.

VeraCrypt-DCS uses EDK II as its UEFI development environement.

VeraCrypt-DCS is licensed under LGPL: https://github.com/veracrypt/VeraCrypt-DCS/blob/master/LICENSE

Here the steps to build VeraCrypt-DCS (Visual Studio 2010 SP1 should be installed)
  * Clone EDK: git clone https://github.com/tianocore/tianocore.github.io.git edk2
  * Switch to UDK2015 branche: git checkout UDK2015
  * Clone VeraCrypt-DCS as DcsPkg inside edk2 folder: git clone https://github.com/veracrypt/VeraCrypt-DCS.git DcsPkg 
  * Switch to VeraCrypt_1.18 branche: git checkout VeraCrypt_1.18
  * Setup EDK by typing edksetup.bat at the root of folder edk2
  * change directoty to DcsPkg and then type setenv.bat.
  * change directory to DcsPkg\Library\VeraCryptLib and then type mklinks_src.bat: you will be asked to provide the path to VeraCrypt src folder.
  * change directory to DcsPkg and then type dcs_bld.bat X64Rel
  * After the build is finished, EFI bootloader files will be present at edk2\Build\DcsPkg\RELEASE_VS2010x86\X64
  
Secure Boot:
In order to allow VeraCrypt EFI bootloader to run when EFI Secure Boot is enabled, VeraCrypt EFI bootloader files are signed by custom key(DCS_sign) whose public part can be loaded into Secure Boot to allow verification of VeraCrypt EFI files.

to update Secure Boot configuration steps:
1. Enter BIOS configuration
2. Switch Secure boot to setup mode (or custom mode). It deletes PK (platform certificate) and allows to load DCS platform key.
3. Boot Windows
4. execute from admin command prompt
   powershell -ExecutionPolicy Bypass -File sb_set_siglists.ps1
It sets in PK (platform key) - DCS_platform
It sets in KEK (key exchange key) - DCS_key_exchange
It sets in db - DCS_sign MicWinProPCA2011_2011-10-19 MicCorUEFCA2011_2011-06-27 

All DCS modules are protected by DCS_sign. 
All Windows modules are protected by MicWinProPCA2011_2011-10-19
All SHIM(linux) modules are protected by MicCorUEFCA2011_2011-06-27