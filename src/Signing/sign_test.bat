PATH=%PATH%;%WSDK81%\bin\x86

set PFXNAME=TestCertificate\idrix_codeSign.pfx
set PFXPASSWORD=idrix

rem sign using SHA-1
signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac TestCertificate\idrix_TestRootCA.crt /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\veracrypt.sys" "..\Release\Setup Files\veracrypt-x64.sys" "..\Release\Setup Files\VeraCrypt.exe" "..\Release\Setup Files\VeraCrypt Format.exe" "..\Release\Setup Files\VeraCryptExpander.exe" "..\Release\Setup Files\VeraCrypt-x64.exe" "..\Release\Setup Files\VeraCrypt Format-x64.exe" "..\Release\Setup Files\VeraCryptExpander-x64.exe"

rem sign using SHA-256
signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac TestCertificate\idrix_TestRootCA.crt /as /fd sha256 /tr http://timestamp.geotrust.com/tsa "..\Release\Setup Files\veracrypt.sys" "..\Release\Setup Files\veracrypt-x64.sys" "..\Release\Setup Files\VeraCrypt.exe" "..\Release\Setup Files\VeraCrypt Format.exe" "..\Release\Setup Files\VeraCryptExpander.exe" "..\Release\Setup Files\VeraCrypt-x64.exe" "..\Release\Setup Files\VeraCrypt Format-x64.exe" "..\Release\Setup Files\VeraCryptExpander-x64.exe"

cd "..\Release\Setup Files\"

copy /V /Y ..\..\..\Translations\*.xml .

"VeraCrypt Setup.exe" /p

del *.xml

cd "..\..\Signing"

rem sign using SHA-1
signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac TestCertificate\idrix_TestRootCA.crt /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\VeraCrypt Setup 1.16.exe"

rem sign using SHA-256
signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac TestCertificate\idrix_TestRootCA.crt /as /fd sha256 /tr http://timestamp.geotrust.com/tsa "..\Release\Setup Files\VeraCrypt Setup 1.16.exe"

pause