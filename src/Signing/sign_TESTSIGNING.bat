PATH=%PATH%;%WSDK81%\bin\x86

set VC_VERSION=1.26.24
set VC_VERSION_NBRE=1.26.24
set SIGNINGPATH=%~dp0
cd %SIGNINGPATH%

rem sign using SHA-256
signtool sign /v /sha1 86E1D426731E79117452F090188A828426B29B5F /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://timestamp.digicert.com /td SHA256 "..\Release\Setup Files\veracrypt-x64.sys" "..\Release\Setup Files\veracrypt-arm64.sys"

signtool sign /v /sha1 86E1D426731E79117452F090188A828426B29B5F /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://timestamp.digicert.com /td SHA256 "..\Release\Setup Files\VeraCrypt-x64.exe" "..\Release\Setup Files\VeraCrypt Format-x64.exe" "..\Release\Setup Files\VeraCryptExpander-x64.exe" "..\Release\Setup Files\VeraCrypt-arm64.exe" "..\Release\Setup Files\VeraCrypt Format-arm64.exe" "..\Release\Setup Files\VeraCryptExpander-arm64.exe" "..\Release\Setup Files\VeraCrypt COMReg.exe" "..\Release\Setup Files\VeraCryptSetup.dll"

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
tar -a -cf Languages.zip Languages
rmdir /S /Q docs
mkdir docs\html\en
mkdir docs\EFI-DCS
xcopy /E /V /Y ..\..\..\doc\html\* docs\html\.
copy "..\..\..\doc\chm\VeraCrypt User Guide*.chm" docs\.
copy "..\..\..\doc\EFI-DCS\*.pdf" docs\EFI-DCS\.
del docs.zip
tar -a -cf docs.zip docs
"VeraCrypt Setup.exe" /p
"VeraCrypt Portable.exe" /p

del LICENSE
del License.txt
del NOTICE
del License.rtf
del VeraCrypt.ico
del VeraCrypt_setup_background.bmp
del VeraCrypt_setup.bmp
del Setup.ico
del "VeraCrypt User Guide*.chm"
del Languages.zip
del docs.zip
rmdir /S /Q Languages
rmdir /S /Q docs

cd %SIGNINGPATH%

rem sign Setup using SHA-256
signtool sign /v /sha1 86E1D426731E79117452F090188A828426B29B5F /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://timestamp.digicert.com /td SHA256 "..\Release\Setup Files\VeraCrypt Setup %VC_VERSION%.exe" "..\Release\Setup Files\VeraCrypt Portable %VC_VERSION%.exe" 

pause
