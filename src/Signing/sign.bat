PATH=%PATH%;%WSDK81%\bin\x86;C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x86

set VC_VERSION=1.26.21
set VC_VERSION_NBRE=1.26.21
set SIGNINGPATH=%~dp0
cd %SIGNINGPATH%

rem call "..\..\doc\chm\create_chm.bat"

cd %SIGNINGPATH%

rem sign using SHA-256
signtool sign /v /sha1 86E1D426731E79117452F090188A828426B29B5F /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://timestamp.digicert.com /td SHA256 "..\Release\Setup Files\VeraCrypt-x64.exe" "..\Release\Setup Files\VeraCrypt Format-x64.exe" "..\Release\Setup Files\VeraCryptExpander-x64.exe" "..\Release\Setup Files\VeraCrypt-arm64.exe" "..\Release\Setup Files\VeraCrypt Format-arm64.exe" "..\Release\Setup Files\VeraCryptExpander-arm64.exe" "..\Release\Setup Files\VeraCryptSetup.dll" 

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

@echo off
setlocal

rem Define the source and target directories
set "SOURCE_DIR=..\..\..\Translations"
set "TARGET_DIR=Languages"

rem Copy files matching Language.xx.xml where xx is any two characters
copy /V /Y "%SOURCE_DIR%\Language.??.xml" "%TARGET_DIR%\."

rem Copy files matching Language.xx-yy.xml where xx and yy are any two characters
copy /V /Y "%SOURCE_DIR%\Language.??-??.xml" "%TARGET_DIR%\."

endlocal
@echo on

del Languages.zip
tar -a -cf Languages.zip Languages
rmdir /S /Q docs
mkdir docs\html
mkdir docs\EFI-DCS
xcopy /E /V /Y ..\..\..\doc\html\* docs\html\.
copy "..\..\..\doc\chm\VeraCrypt User Guide*.chm" docs\.
copy "..\..\..\doc\EFI-DCS\*.pdf" docs\EFI-DCS\.
del docs.zip
tar -a -cf docs.zip docs
"VeraCrypt Setup.exe" /p
"VeraCrypt Portable.exe" /p
VeraCryptCOMRegBase.exe /p

cd %SIGNINGPATH%
signtool sign /v /sha1 86E1D426731E79117452F090188A828426B29B5F /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://timestamp.digicert.com /td SHA256 "..\Release\Setup Files\VeraCrypt COMReg.exe"

cd "..\Release\Setup Files\"
call build_msi_x64.bat %VC_VERSION_NBRE%
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
signtool sign /v /sha1 86E1D426731E79117452F090188A828426B29B5F /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://timestamp.digicert.com /td SHA256 "..\Release\Setup Files\VeraCrypt Setup %VC_VERSION%.exe" "..\Release\Setup Files\VeraCrypt Portable %VC_VERSION%.exe" "..\Release\Setup Files\bin\VeraCrypt_Setup_x64_%VC_VERSION_NBRE%.msi" "..\Release\Setup Files\bin\VeraCrypt_Setup_x64_%VC_VERSION_NBRE%_en-us.msi"

pause
