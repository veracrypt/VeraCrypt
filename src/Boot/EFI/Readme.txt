To update secure boot configuration
1. Enter BIOS configuration
2. Switch Secure boot to setup mode (or custom mode). It deletes PK (platform certificate) and allows to load DCS platform key.
3. Boot Windows
4. execute from admin command prompt
   powershell -File sb_set_siglists.ps1
It sets in PK (platform key) - DCS_platform
It sets in KEK (key exchange key) - DCS_key_exchange
It sets in db - DCS_sign MicWinProPCA2011_2011-10-19 MicCorUEFCA2011_2011-06-27 

All DCS modules are protected by DCS_sign. 
All Windows modules are protected by MicWinProPCA2011_2011-10-19
All SHIM(linux) modules are protected by MicCorUEFCA2011_2011-06-27 