PATH=%PATH%;%WSDK81%\bin\x86;C:\Program Files\7-Zip;C:\Program Files (x86)\7-Zip

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

rem sign using SHA-1
signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac %PFXCA% /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Debug\Setup Files\veracrypt.sys" "..\Debug\Setup Files\veracrypt-x64.sys" "..\Debug\Setup Files\VeraCrypt.exe" "..\Debug\Setup Files\VeraCrypt Format.exe" "..\Debug\Setup Files\VeraCryptExpander.exe" "..\Debug\Setup Files\VeraCrypt-x64.exe" "..\Debug\Setup Files\VeraCrypt Format-x64.exe" "..\Debug\Setup Files\VeraCryptExpander-x64.exe"

rem sign using SHA-256
signtool sign /v /a /f %SHA256PFXNAME% /p %SHA256PFXPASSWORD% /ac %SHA256PFXCA% /as /fd sha256 /tr http://timestamp.globalsign.com/?signature=sha2 /td SHA256 "..\Debug\Setup Files\veracrypt.sys" "..\Debug\Setup Files\veracrypt-x64.sys" "..\Debug\Setup Files\VeraCrypt.exe" "..\Debug\Setup Files\VeraCrypt Format.exe" "..\Debug\Setup Files\VeraCryptExpander.exe" "..\Debug\Setup Files\VeraCrypt-x64.exe" "..\Debug\Setup Files\VeraCrypt Format-x64.exe" "..\Debug\Setup Files\VeraCryptExpander-x64.exe"

cd "..\Debug\Setup Files\"

copy ..\..\LICENSE .
copy ..\..\License.txt .
copy ..\..\NOTICE .

del *.xml
copy /V /Y ..\..\..\Translations\*.xml .

rmdir /S /Q docs
mkdir docs\html\en
copy /V /Y ..\..\..\doc\html\* docs\html\en\.
copy "..\..\..\doc\chm\VeraCrypt User Guide.chm" docs\.

del docs.zip
7z a -y docs.zip docs

"VeraCrypt Setup.exe" /p

del LICENSE
del License.txt
del NOTICE
del "VeraCrypt User Guide.chm"

del *.xml
del docs.zip
rmdir /S /Q docs

cd %SIGNINGPATH%

rem sign using SHA-1
signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac %PFXCA% /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Debug\Setup Files\VeraCrypt Setup 1.20-BETA2.exe"

rem sign using SHA-256
signtool sign /v /a /f %SHA256PFXNAME% /p %SHA256PFXPASSWORD% /ac %SHA256PFXCA% /as /fd sha256 /tr http://timestamp.globalsign.com/?signature=sha2 /td SHA256 "..\Debug\Setup Files\VeraCrypt Setup 1.20-BETA2.exe"

pause