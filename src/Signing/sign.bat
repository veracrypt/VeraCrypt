PATH=%PATH%;%WSDK81%\bin\x86;C:\Program Files\7-Zip;C:\Program Files (x86)\7-Zip

set SIGNINGPATH=%~dp0
cd %SIGNINGPATH%

call "..\..\doc\chm\create_chm.bat"

cd %SIGNINGPATH%

rem sign using SHA-1
signtool sign /v /a /n IDRIX /i Thawte /ac thawte_Primary_MS_Cross_Cert.cer /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\veracrypt.sys" "..\Release\Setup Files\veracrypt-x64.sys"
signtool sign /v /a /n IDRIX /i Thawte /ac Thawt_CodeSigning_CA.crt /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\VeraCrypt.exe" "..\Release\Setup Files\VeraCrypt Format.exe" "..\Release\Setup Files\VeraCryptExpander.exe" "..\Release\Setup Files\VeraCrypt-x64.exe" "..\Release\Setup Files\VeraCrypt Format-x64.exe" "..\Release\Setup Files\VeraCryptExpander-x64.exe"

rem sign using SHA-256
signtool sign /v /a /n "IDRIX SARL" /i GlobalSign /ac GlobalSign_Root_CA_MS_Cross_Cert.crt /as /fd sha256 /tr http://timestamp.globalsign.com/?signature=sha2 /td SHA256 "..\Release\Setup Files\veracrypt.sys" "..\Release\Setup Files\veracrypt-x64.sys"
signtool sign /v /a /n "IDRIX SARL" /i GlobalSign /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /as /fd sha256 /tr http://timestamp.globalsign.com/?signature=sha2 /td SHA256 "..\Release\Setup Files\VeraCrypt.exe" "..\Release\Setup Files\VeraCrypt Format.exe" "..\Release\Setup Files\VeraCryptExpander.exe" "..\Release\Setup Files\VeraCrypt-x64.exe" "..\Release\Setup Files\VeraCrypt Format-x64.exe" "..\Release\Setup Files\VeraCryptExpander-x64.exe"


cd "..\Release\Setup Files\"

copy ..\..\LICENSE .
copy ..\..\License.txt .
copy ..\..\NOTICE .

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

del LICENSE
del License.txt
del NOTICE
del "VeraCrypt User Guide.chm"

del Languages.zip
del docs.zip
rmdir /S /Q Languages
rmdir /S /Q docs

cd %SIGNINGPATH%

rem sign using SHA-1
signtool sign /v /a /n IDRIX /i Thawte /ac Thawt_CodeSigning_CA.crt /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll "..\Release\Setup Files\VeraCrypt Setup 1.22-BETA2-Build5.exe"
rem sign using SHA-256
signtool sign /v /a /n "IDRIX SARL" /i GlobalSign /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /as /fd sha256 /tr http://timestamp.globalsign.com/?signature=sha2 /td SHA256 "..\Release\Setup Files\VeraCrypt Setup 1.22-BETA2-Build5.exe"

pause
