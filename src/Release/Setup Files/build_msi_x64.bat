::------------------------------------
::Define search paths here for Wix ToolSet and SDK (and SignTool optionnally)
::------------------------------------

@set SEARCH_WIX_PATH=C:\Program Files (x86)\WiX Toolset v3.14\bin

@set SEARCH_VC_DIR_PLATFORMSDK_1=C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x86
@set SEARCH_VC_DIR_PLATFORMSDK_2=C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x86
@set SEARCH_VC_DIR_PLATFORMSDK_3=C:\Program Files (x86)\Windows Kits\10\bin\10.0.17134.0\x86
@set SEARCH_VC_DIR_PLATFORMSDK_4=C:\Program Files (x86)\Windows Kits\10\bin\x86
@set SEARCH_VC_DIR_PLATFORMSDK_5=C:\Program Files\Microsoft Platform SDK\bin
@set SEARCH_VC_DIR_PLATFORMSDK_6=C:\Program Files (x86)\Windows Kits\8.1\bin\x86
@set SEARCH_VC_DIR_PLATFORMSDK_7=C:\Program Files (x86)\Windows Kits\8.0\bin\x86
@set SEARCH_VC_DIR_PLATFORMSDK_8=C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\bin

::end of search paths

set MSI_BUILDPATH=%~dp0
cd %MSI_BUILDPATH%

::------------------------------------
:: Look for msitran.exe and msidb.exe
::------------------------------------

@echo [INFO] Define default value for VC_DIR_PLATFORMSDK if not defined yet
@echo [INFO] Input VC_DIR_PLATFORMSDK=%VC_DIR_PLATFORMSDK%
@set FILE_TO_FIND="msitran.exe" "msidb.exe"
@echo [INFO] Looking for files: %FILE_TO_FIND%

@set FILE_NOT_FOUND=
@for %%i in (%FILE_TO_FIND%) do @if not exist "%VC_DIR_PLATFORMSDK%\%%~i" set FILE_NOT_FOUND=%%~i
@if "%FILE_NOT_FOUND%"=="" goto found_mssdk
@echo        Not found in "%VC_DIR_PLATFORMSDK%"

@set VC_DIR_PLATFORMSDK=%SEARCH_VC_DIR_PLATFORMSDK_1%
@set FILE_NOT_FOUND=
@for %%i in (%FILE_TO_FIND%) do @if not exist "%VC_DIR_PLATFORMSDK%\%%~i" set FILE_NOT_FOUND=%%~i
@if "%FILE_NOT_FOUND%"=="" goto found_mssdk
@echo        Not found in "%VC_DIR_PLATFORMSDK%"

@set VC_DIR_PLATFORMSDK=%SEARCH_VC_DIR_PLATFORMSDK_2%
@set FILE_NOT_FOUND=
@for %%i in (%FILE_TO_FIND%) do @if not exist "%VC_DIR_PLATFORMSDK%\%%~i" set FILE_NOT_FOUND=%%~i
@if "%FILE_NOT_FOUND%"=="" goto found_mssdk
@echo        Not found in "%VC_DIR_PLATFORMSDK%"

@set VC_DIR_PLATFORMSDK=%SEARCH_VC_DIR_PLATFORMSDK_3%
@set FILE_NOT_FOUND=
@for %%i in (%FILE_TO_FIND%) do @if not exist "%VC_DIR_PLATFORMSDK%\%%~i" set FILE_NOT_FOUND=%%~i
@if "%FILE_NOT_FOUND%"=="" goto found_mssdk
@echo        Not found in "%VC_DIR_PLATFORMSDK%"

@rem paths for Windows 8 SDK are slightly different
@set FILE_TO_FIND="msitran.exe" "msidb.exe"

@set VC_DIR_PLATFORMSDK=%SEARCH_VC_DIR_PLATFORMSDK_4%
@set FILE_NOT_FOUND=
@for %%i in (%FILE_TO_FIND%) do @if not exist "%VC_DIR_PLATFORMSDK%\%%~i" set FILE_NOT_FOUND=%%~i
@if "%FILE_NOT_FOUND%"=="" goto found_mssdk
@echo        Not found in "%VC_DIR_PLATFORMSDK%"

@set VC_DIR_PLATFORMSDK=%SEARCH_VC_DIR_PLATFORMSDK_5%
@set FILE_NOT_FOUND=
@for %%i in (%FILE_TO_FIND%) do @if not exist "%VC_DIR_PLATFORMSDK%\%%~i" set FILE_NOT_FOUND=%%~i
@if "%FILE_NOT_FOUND%"=="" goto found_mssdk
@echo        Not found in "%VC_DIR_PLATFORMSDK%"

@set VC_DIR_PLATFORMSDK=%SEARCH_VC_DIR_PLATFORMSDK_6%
@set FILE_NOT_FOUND=
@for %%i in (%FILE_TO_FIND%) do @if not exist "%VC_DIR_PLATFORMSDK%\%%~i" set FILE_NOT_FOUND=%%~i
@if "%FILE_NOT_FOUND%"=="" goto found_mssdk
@echo        Not found in "%VC_DIR_PLATFORMSDK%"

@echo [ERROR] MS Platform SDK 2008, Windows SDK v7.1, or Windows SDK 8.0/8.1/10 could not be found
@echo         If the path is not any of the above,
@echo         please define VC_DIR_PLATFORMSDK environment variable.
@exit /B 1

:found_mssdk
@echo        Found in "%VC_DIR_PLATFORMSDK%"

::------------------------------------
:: Look for candle.exe (and light.exe obviously)
::------------------------------------

@echo [INFO] Check if WiX is installed
@echo [INFO] Default value for VC_DIR_WIX is set to %WIX%
@set VC_DIR_WIX=%WIX%
@set FILE_TO_FIND="candle.exe"
@echo [INFO] Looking for files: %FILE_TO_FIND%

@set FILE_NOT_FOUND=
@for %%i in (%FILE_TO_FIND%) do @if not exist "%VC_DIR_WIX%\%%~i" set FILE_NOT_FOUND=%%~i
@if "%FILE_NOT_FOUND%"=="" goto found_wix
@echo        Not found in "%VC_DIR_WIX%"

@set VC_DIR_WIX=%SEARCH_WIX_PATH%
@set FILE_NOT_FOUND=
@for %%i in (%FILE_TO_FIND%) do @if not exist "%VC_DIR_WIX%\%%~i" set FILE_NOT_FOUND=%%~i
@if "%FILE_NOT_FOUND%"=="" goto found_wix
@echo        Not found in "%VC_DIR_WIX%"

@echo [ERROR] WiX could not be found
@echo         Please install Wix3
@exit /B 1

:found_wix
@echo        Found in "%VC_DIR_WIX%"

::------------------------------------
:: Create a MSI installer for each language
:: We make use of -sice:ICE09 to silence ICE09 warnings generated because we install non-permanent elements to 'SystemFolder'
::------------------------------------
@echo [INFO] Creating msi 64-bit installers

@echo [INFO] Making the en-us version in %cd%\out\64\en-us\
"%VC_DIR_WIX%\candle.exe" -dLang=en -arch x64 -ext WixUIExtension -ext WiXUtilExtension Product64.wxs -out out\64\en-us\Product.wixobj
@if NOT "%ERRORLEVEL%" == "0" goto msi_failed
"%VC_DIR_WIX%\candle.exe" -dLang=en -arch x64 -ext WixUIExtension -ext WiXUtilExtension Custom_InstallDir.wxs -out out\64\en-us\Custom_InstallDir.wixobj
@if NOT "%ERRORLEVEL%" == "0" goto msi_failed
"%VC_DIR_WIX%\candle.exe" -dLang=en -arch x64 -ext WixUIExtension -ext WiXUtilExtension Custom_InstallDirDlg.wxs -out out\64\en-us\Custom_InstallDirDlg.wixobj
@if NOT "%ERRORLEVEL%" == "0" goto msi_failed
"%VC_DIR_WIX%\Light.exe" -ext WixUIExtension -ext WiXUtilExtension -cultures:en-us -loc Strings-en.wxl out\64\en-us\Product.wixobj out\64\en-us\Custom_InstallDirDlg.wixobj out\64\en-us\Custom_InstallDir.wixobj -out out\64\en-us\VeraCrypt_Setup_%1_en-us.msi -pdbout out\64\en-us\VeraCrypt_Setup_%1_en-us.wixpdb -sice:ICE09
@if NOT "%ERRORLEVEL%" == "0" goto msi_failed

::------------------------------------
:: Join the language specific MSIs together
::------------------------------------
@echo [INFO] Joining msi 64-bit installers into 1 64-bit installer

@set OUT_PATH=%cd%\out\64\
@echo [INFO] OUT_PATH=%OUT_PATH%

@set MSI_FILE_IN=VeraCrypt_Setup_%1
@set MSI_FILE_OUT=VeraCrypt_Setup_x64_%1

:: Check if all the MSI files were built
@set LANG=en-us
@IF NOT EXIST "%OUT_PATH%\%LANG%\%MSI_FILE_IN%_%LANG%.msi" goto NOT_%LANG%

:: Take all the MSI files and process
@set LANG=en-us
@copy /Y "%OUT_PATH%\%LANG%\%MSI_FILE_IN%_%LANG%.msi" "%OUT_PATH%\%MSI_FILE_OUT%.msi"

::------------------------------------
:: Add all available LCIDs
::------------------------------------
"%VC_DIR_PLATFORMSDK%\MsiInfo.Exe" "%OUT_PATH%\%MSI_FILE_OUT%.msi" /p x64;1033
@if NOT "%ERRORLEVEL%" == "0" goto comb_msi_failed

::------------------------------------
:: Copy to bin and remove out
::------------------------------------
mkdir bin
@copy /Y "%OUT_PATH%\%MSI_FILE_OUT%.msi" "%cd%\bin\%MSI_FILE_OUT%.msi"
@set LANG=en-us
@copy /Y "%OUT_PATH%\%LANG%\%MSI_FILE_IN%_%LANG%.msi" "%cd%\bin\%MSI_FILE_OUT%_%LANG%.msi"
@rmdir /S /Q "%cd%\out"

goto END

:msi_failed
@echo [ERR ] failed to create the MSI
@exit /B 1

:comb_msi_failed
@echo [ERR ] failed to combine the language specific MSI's
@exit /B 1

:NOT_en-us
@echo [ERR ] Missing file '%OUT_PATH%\%LANG%\%MSI_FILE_IN%_%LANG%.msi'
@exit /B 1

:NOT_lv-lv
@echo [ERR ] Missing file '%OUT_PATH%\%LANG%\%MSI_FILE_IN%_%LANG%.msi'
@exit /B 1

@echo [INFO] Done creating multi-lang msi installers
:END
@echo end