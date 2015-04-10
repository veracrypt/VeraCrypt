PATH=%PATH%;%DDK%\bin\x86

set PFXNAME=TestCertificate\idrix_codeSign.pfx
set PFXPASSWORD=idrix

signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac TestCertificate\idrix_TestRootCA.crt /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\veracrypt.sys"
signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac TestCertificate\idrix_TestRootCA.crt /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\veracrypt-x64.sys"

signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac TestCertificate\idrix_TestRootCA.crt /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\VeraCrypt.exe"
signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac TestCertificate\idrix_TestRootCA.crt /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\VeraCrypt Format.exe"
signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac TestCertificate\idrix_TestRootCA.crt /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\VeraCryptExpander.exe"

cd "..\Release\Setup Files\"

copy /V /Y ..\..\..\Translations\*.xml .

"VeraCrypt Setup.exe" /p

del *.xml

cd "..\..\Signing"

signtool sign /v /a /f %PFXNAME% /p %PFXPASSWORD% /ac TestCertificate\idrix_TestRootCA.crt /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\VeraCrypt Setup 1.0f-2.exe"

pause