PATH=%PATH%;%WSDK81%\bin\x86

rem sign using SHA-1
signtool sign /v /a /n IDRIX /ac thawte_Primary_MS_Cross_Cert.cer /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\veracrypt.sys" "..\Release\Setup Files\veracrypt-x64.sys"
signtool sign /v /a /n IDRIX /ac Thawt_CodeSigning_CA.crt /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\VeraCrypt.exe" "..\Release\Setup Files\VeraCrypt Format.exe" "..\Release\Setup Files\VeraCryptExpander.exe" "..\Release\Setup Files\VeraCrypt-x64.exe" "..\Release\Setup Files\VeraCrypt Format-x64.exe" "..\Release\Setup Files\VeraCryptExpander-x64.exe"

rem sign using SHA-256
signtool sign /v /a /n IDRIX /ac thawte_Primary_MS_Cross_Cert.cer /as /fd sha256 /tr http://timestamp.geotrust.com/tsa "..\Release\Setup Files\veracrypt.sys" "..\Release\Setup Files\veracrypt-x64.sys"
signtool sign /v /a /n IDRIX /ac Thawt_CodeSigning_CA.crt /as /fd sha256 /tr http://timestamp.geotrust.com/tsa "..\Release\Setup Files\VeraCrypt.exe" "..\Release\Setup Files\VeraCrypt Format.exe" "..\Release\Setup Files\VeraCryptExpander.exe" "..\Release\Setup Files\VeraCrypt-x64.exe" "..\Release\Setup Files\VeraCrypt Format-x64.exe" "..\Release\Setup Files\VeraCryptExpander-x64.exe"

cd "..\Release\Setup Files\"

copy /V /Y ..\..\..\Translations\*.xml .

"VeraCrypt Setup.exe" /p

del *.xml

cd "..\..\Signing"

rem sign using SHA-1
signtool sign /v /a /n IDRIX /ac Thawt_CodeSigning_CA.crt /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\VeraCrypt Setup 1.16.exe"
rem sign using SHA-256
signtool sign /v /a /n IDRIX /ac Thawt_CodeSigning_CA.crt /as /fd sha256 /tr http://timestamp.geotrust.com/tsa "..\Release\Setup Files\VeraCrypt Setup 1.16.exe"

pause
