PATH=%PATH%;%WSDK81%\bin\x86;C:\Program Files\7-Zip;C:\Program Files (x86)\7-Zip

set VC_VERSION=1.24-Update9
set VC_VERSION_NBRE=1.24.25
set SIGNINGPATH=%~dp0
cd %SIGNINGPATH%

call "..\..\doc\chm\create_chm.bat"

cd %SIGNINGPATH%

rem sign using SHA-1
signtool sign /v /sha1 85aa2e55cfb9c38fe474c58b38e9521450cd9306 /ac DigiCert_Assured_ID_MS_Cross_Cert.crt /fd sha1 /t http://timestamp.digicert.com "..\Release\Setup Files\veracrypt.sys" "..\Release\Setup Files\veracrypt-x64.sys"
signtool sign /v /sha1 85aa2e55cfb9c38fe474c58b38e9521450cd9306 /ac DigiCert_Assured_ID_Code_Signing_CA.cer /fd sha1 /t http://timestamp.digicert.com "..\Release\Setup Files\VeraCrypt.exe" "..\Release\Setup Files\VeraCrypt Format.exe" "..\Release\Setup Files\VeraCryptExpander.exe" "..\Release\Setup Files\VeraCrypt-x64.exe" "..\Release\Setup Files\VeraCrypt Format-x64.exe" "..\Release\Setup Files\VeraCryptExpander-x64.exe" "..\Release\Setup Files\VeraCrypt COMReg.exe"

timeout /t 10

rem sign using SHA-256
signtool sign /v /sha1 04141E4EA6D9343CEC994F6C099DC09BDD8937C9 /ac GlobalSign_R3Cross.cer /as /fd sha256 /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "..\Release\Setup Files\veracrypt.sys" "..\Release\Setup Files\veracrypt-x64.sys"
signtool sign /v /sha1 04141E4EA6D9343CEC994F6C099DC09BDD8937C9 /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /as /fd sha256 /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "..\Release\Setup Files\VeraCrypt.exe" "..\Release\Setup Files\VeraCrypt Format.exe" "..\Release\Setup Files\VeraCryptExpander.exe" "..\Release\Setup Files\VeraCrypt-x64.exe" "..\Release\Setup Files\VeraCrypt Format-x64.exe" "..\Release\Setup Files\VeraCryptExpander-x64.exe" "..\Release\Setup Files\VeraCrypt COMReg.exe"

rem create setup and MSI
cd "..\Release\Setup Files\"
copy ..\..\LICENSE .
copy ..\..\License.txt .
copy ..\..\NOTICE .
copy ..\..\Resources\Texts\License.rtf .
copy ..\..\Common\VeraCrypt.ico .
copy ..\..\Setup\VeraCrypt_setup_background.bmp .
copy ..\..\Setup\VeraCrypt_setup.bmp .
copy ..\..\Setup\Setup.ico .
del *.xml
rmdir /S /Q Languages
mkdir Languages
copy /V /Y ..\..\..\Translations\*.xml Languages\.
del Languages.zip
7z a -y Languages.zip Languages
rmdir /S /Q docs
mkdir docs\html\en
mkdir docs\EFI-DCS
copy /V /Y ..\..\..\doc\html\* docs\html\en\.
copy "..\..\..\doc\chm\VeraCrypt User Guide.chm" docs\.
copy "..\..\..\doc\EFI-DCS\*.pdf" docs\EFI-DCS\.
del docs.zip
7z a -y docs.zip docs
"VeraCrypt Setup.exe" /p
"VeraCrypt Portable.exe" /p
call build_msi_x64.bat %VC_VERSION_NBRE%
del LICENSE
del License.txt
del NOTICE
del License.rtf
del VeraCrypt.ico
del VeraCrypt_setup_background.bmp
del VeraCrypt_setup.bmp
del Setup.ico
del "VeraCrypt User Guide.chm"
del Languages.zip
del docs.zip
rmdir /S /Q Languages
rmdir /S /Q docs

cd %SIGNINGPATH%

rem Can't dual-sign MSI files when using signtool (only jsign / osslsigncode can do that)

rem sign using SHA-1
signtool sign /v /sha1 85aa2e55cfb9c38fe474c58b38e9521450cd9306 /ac DigiCert_Assured_ID_Code_Signing_CA.cer /fd sha1 /t http://timestamp.digicert.com "..\Release\Setup Files\VeraCrypt Setup %VC_VERSION%.exe" "..\Release\Setup Files\VeraCrypt Portable %VC_VERSION%.exe"

timeout /t 10

rem dual sign Setup using SHA-256
signtool sign /v /sha1 04141E4EA6D9343CEC994F6C099DC09BDD8937C9 /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /as /fd sha256 /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "..\Release\Setup Files\VeraCrypt Setup %VC_VERSION%.exe" "..\Release\Setup Files\VeraCrypt Portable %VC_VERSION%.exe" "..\Release\Setup Files\bin\VeraCrypt_%VC_VERSION_NBRE%_Setup_x64.msi" "..\Release\Setup Files\bin\VeraCrypt_%VC_VERSION_NBRE%_Setup_x64_en-us.msi" 

rem single sign MSI using SHA-256
signtool sign /v /sha1 04141E4EA6D9343CEC994F6C099DC09BDD8937C9 /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "..\Release\Setup Files\bin\VeraCrypt_%VC_VERSION_NBRE%_Setup_x64.msi" "..\Release\Setup Files\bin\VeraCrypt_%VC_VERSION_NBRE%_Setup_x64_en-us.msi" 

move "..\Release\Setup Files\VeraCrypt Setup %VC_VERSION%.exe" "..\Release\Setup Files\VeraCrypt Legacy Setup %VC_VERSION%.exe"
move "..\Release\Setup Files\VeraCrypt Portable %VC_VERSION%.exe" "..\Release\Setup Files\VeraCrypt Legacy Portable %VC_VERSION%.exe"

pause
