The source code for VeraCrypt EFI bootloader files is available at: https://github.com/veracrypt/VeraCrypt-DCS

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
  