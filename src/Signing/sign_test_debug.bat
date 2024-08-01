PATH=%PATH%;%WSDK81%\bin\x86;C:\Program Files\7-Zip;C:\Program Files (x86)\7-Zip
set VC_VERSION=1.26.13
set VC_VERSION_NBRE=1.26.13
set PFXNAME=TestCertificate\idrix_codeSign.pfx
set PFXPASSWORD=idrix
set PFXCA=TestCertificate\idrix_TestRootCA.crt
set SHA256PFXNAME=TestCertificate\idrix_Sha256CodeSign.pfx
set SHA256PFXPASSWORD=idrix
set SHA256PFXCA=TestCertificate\idrix_SHA256TestRootCA.crt

set SIGNINGPATH=%~dp0
cd %SIGNINGPATH%

call "..\..\doc\chm\create_chm.bat"

cd %SIGNINGPATH%


rem sign using SHA-256
signtool sign /v /a /f %SHA256PFXNAME% /p %SHA256PFXPASSWORD% /ac %SHA256PFXCA% /fd sha256 /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "..\Debug\Setup Files\veracrypt.sys" "..\Debug\Setup Files\veracrypt-x64.sys" "..\Debug\Setup Files\veracrypt-arm64.sys" "..\Debug\Setup Files\VeraCrypt.exe" "..\Debug\Setup Files\VeraCrypt Format.exe" "..\Debug\Setup Files\VeraCryptExpander.exe" "..\Debug\Setup Files\VeraCrypt-x64.exe" "..\Debug\Setup Files\VeraCrypt Format-x64.exe" "..\Debug\Setup Files\VeraCryptExpander-x64.exe" "..\Debug\Setup Files\VeraCrypt-arm64.exe" "..\Debug\Setup Files\VeraCrypt Format-arm64.exe" "..\Debug\Setup Files\VeraCryptExpander-arm64.exe" "..\Debug\Setup Files\VeraCrypt COMReg.exe"

rem create setup and MSI
cd "..\Debug\Setup Files\"
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
copy "..\..\Release\Setup Files\*.cat" .
copy "..\..\Release\Setup Files\veracrypt.inf" .
del docs.zip
7z a -y docs.zip docs
"VeraCrypt Setup.exe" /p
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
signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac %PFXCA% /fd sha1 /t http://timestamp.digicert.com "..\Debug\Setup Files\VeraCrypt Setup %VC_VERSION%.exe"

timeout /t 10

rem dual-sign Setup using SHA-256
signtool sign /v /a /f %SHA256PFXNAME% /p %SHA256PFXPASSWORD% /ac %SHA256PFXCA% /as /fd sha256 /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "..\Debug\Setup Files\VeraCrypt Setup %VC_VERSION%.exe"

rem single sign MSI using SHA-256
signtool sign /v /a /f %SHA256PFXNAME% /p %SHA256PFXPASSWORD% /ac %SHA256PFXCA% /fd sha256 /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "..\Debug\Setup Files\bin\VeraCrypt_Setup_x64_%VC_VERSION_NBRE%.msi" "..\Debug\Setup Files\bin\VeraCrypt_Setup_x64_%VC_VERSION_NBRE%_en-us.msi" 

pause