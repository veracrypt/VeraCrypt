@echo off
setlocal EnableDelayedExpansion

:: Define constants
set "VERACRYPT_PATH=c:\Program Files\VeraCrypt\veracrypt.exe"
set "PASSWORD=test"
set "HIDDEN_PASSWORD=testhidden"

:: Find a free drive letter
call :freedrive mydriveletter || (
    echo ERROR: No free drive letter found.
    goto :exit
)

echo Using drive letter !mydriveletter!: for our tests
echo.

:: Define an array of hash algorithms and their corresponding container files
set "algorithms[0]=sha512,test.sha512.hc"
set "algorithms[1]=whirlpool,test.whirlpool.hc"
set "algorithms[2]=sha256,test.sha256.hc"
set "algorithms[3]=blake2s,test.blake2s.hc"
set "algorithms[4]=streebog,test.streebog.hc"

:: Loop through each algorithm
for /L %%i in (0,1,4) do (
    for /F "tokens=1,2 delims=," %%a in ("!algorithms[%%i]!") do (
        set "hash=%%a"
        set "container=%%b"
        
        if exist "!container!" (
            call :mount_and_measure "!hash!" "!container!" "Normal" "!PASSWORD!"
            call :mount_and_measure "!hash!" "!container!" "Hidden" "!HIDDEN_PASSWORD!"
            echo.
        )
    )
)

:: Autodetect test
call :availablevolume testvolume || goto :exit

call :measure_time "Wrong Password (PRF Auto-detection)" ^
    "/volume !testvolume! /l !mydriveletter! /password wrongpassword /q /silent /m ro"

echo.
goto :exit

:: Subroutine to mount a volume and measure the time taken
:mount_and_measure
setlocal 
set "hash=%~1"
set "container=%~2"
set "type=%~3"
set "volumepassword=%~4"

call :measure_time "%hash% (%type%)" ^
    "/volume !container! /hash !hash! /l !mydriveletter! /password !volumepassword! /q /silent /m ro"

if not exist !mydriveletter!:\ (
    echo ERROR: Drive letter !mydriveletter!: does not exist after mount operation.
    goto :exit
)

"!VERACRYPT_PATH!" /dismount !mydriveletter! /silent /q
exit /b

:: Subroutine to measure the time taken for a command to execute
:measure_time
setlocal 
set "oper=%~1"
set "command=%~2"

for /F "tokens=1-4 delims=:.," %%a in ("!time!") do set /A "start=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"

"!VERACRYPT_PATH!" %command%

for /F "tokens=1-4 delims=:.," %%a in ("!time!") do set /A "end=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"

set /A elapsed=end-start
set /A hh=elapsed/(60*60*100), rest=elapsed%%(60*60*100), mm=rest/(60*100), rest%%=60*100, ss=rest/100, cc=rest%%100
if %hh% lss 10 set hh=0%hh%
if %mm% lss 10 set mm=0%mm%
if %ss% lss 10 set ss=0%ss%
if %cc% lss 10 set cc=0%cc%

echo %oper% = %hh%:%mm%:%ss%,%cc%
exit /b

rem Finds a free drive letter.
rem
rem Parameters:
rem     %1 = Output variable name.
rem
rem Example:
rem     call :freedrive mydriveletter && goto :cont
rem     echo ERROR: No free drive letter found.
rem     goto :EOF
rem     :cont
rem     echo Found drive letter: %mydriveletter%
:freedrive
setlocal EnableDelayedExpansion
set exitcode=0
set "output_var=%~1"
for %%i in (C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z) do (
    set "drive=%%i:"
    rem If 'subst' fails, the drive letter is already in use.
    rem This way we can even detect optical drives that have a drive
    rem letter but no media in them, a case that goes undetected when
    rem using 'if exist'.
    subst !drive! %SystemDrive%\ >nul
    if !errorlevel! == 0 (
        subst !drive! /d >nul
		set "drive=%%i"
        goto :freedrive0
    )
)
set exitcode=1
set drive=
:freedrive0
endlocal & set "%output_var%=%drive%" & exit /b %exitcode%

:: Subroutine to find an available volume
:availablevolume
setlocal EnableDelayedExpansion
set exitcode=0
set "output_var=%~1"
for %%i in (test.sha512.hc,test.sha256.hc,test.whirlpool.hc,test.blake2s.hc) do (
    if exist %%i (
        set "volume=%%i"
        goto :availablevolume0
    )
)
set exitcode=1
set volume=
:availablevolume0
endlocal & set "%output_var%=%volume%" & exit /b %exitcode%

:exit

pause