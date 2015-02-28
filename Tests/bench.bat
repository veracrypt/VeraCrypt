@echo off

setlocal

call :freedrive mydriveletter && goto :cont
echo ERROR: No free drive letter found.
goto :exit
:cont

echo Using drive letter %mydriveletter%: for our tests
echo.

rem Get start time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "start=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Mount SHA-512 container (Normal)
"c:\Program Files\VeraCrypt\veracrypt.exe" /volume test.sha512.hc /hash sha512 /l %mydriveletter% /password test /q /silent /m ro

rem Get end time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "end=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Get elapsed time:
set /A elapsed=end-start

rem Show elapsed time:
set /A hh=elapsed/(60*60*100), rest=elapsed%%(60*60*100), mm=rest/(60*100), rest%%=60*100, ss=rest/100, cc=rest%%100
if %hh% lss 10 set hh=0%hh%
if %mm% lss 10 set mm=0%mm%
if %ss% lss 10 set ss=0%ss%
if %cc% lss 10 set cc=0%cc%
echo SHA-512 (Normal) = %hh%:%mm%:%ss%,%cc%

"c:\Program Files\VeraCrypt\veracrypt.exe" /dismount %mydriveletter% /silent /q

rem Get start time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "start=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Mount SHA-512 container (Hidden)
"c:\Program Files\VeraCrypt\veracrypt.exe" /volume test.sha512.hc /hash sha512 /l %mydriveletter% /password testhidden /q /silent /m ro

rem Get end time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "end=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Get elapsed time:
set /A elapsed=end-start

rem Show elapsed time:
set /A hh=elapsed/(60*60*100), rest=elapsed%%(60*60*100), mm=rest/(60*100), rest%%=60*100, ss=rest/100, cc=rest%%100
if %hh% lss 10 set hh=0%hh%
if %mm% lss 10 set mm=0%mm%
if %ss% lss 10 set ss=0%ss%
if %cc% lss 10 set cc=0%cc%
echo SHA-512 (Hidden) = %hh%:%mm%:%ss%,%cc%
echo.

"c:\Program Files\VeraCrypt\veracrypt.exe" /dismount %mydriveletter% /silent /q

rem Get start time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "start=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Mount Whirlpool container (Normal).
"c:\Program Files\VeraCrypt\veracrypt.exe" /volume test.whirlpool.hc /hash whirlpool /l %mydriveletter% /password test /q /silent /m ro

rem Get end time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "end=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Get elapsed time:
set /A elapsed=end-start

rem Show elapsed time:
set /A hh=elapsed/(60*60*100), rest=elapsed%%(60*60*100), mm=rest/(60*100), rest%%=60*100, ss=rest/100, cc=rest%%100
if %hh% lss 10 set hh=0%hh%
if %mm% lss 10 set mm=0%mm%
if %ss% lss 10 set ss=0%ss%
if %cc% lss 10 set cc=0%cc%
echo Whirlpool (Normal) = %hh%:%mm%:%ss%,%cc%

"c:\Program Files\VeraCrypt\veracrypt.exe" /dismount %mydriveletter% /silent /q

rem Get start time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "start=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Mount Whirlpool container (Hidden).
"c:\Program Files\VeraCrypt\veracrypt.exe" /volume test.whirlpool.hc /hash whirlpool /l %mydriveletter% /password testhidden /q /silent /m ro

rem Get end time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "end=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Get elapsed time:
set /A elapsed=end-start

rem Show elapsed time:
set /A hh=elapsed/(60*60*100), rest=elapsed%%(60*60*100), mm=rest/(60*100), rest%%=60*100, ss=rest/100, cc=rest%%100
if %hh% lss 10 set hh=0%hh%
if %mm% lss 10 set mm=0%mm%
if %ss% lss 10 set ss=0%ss%
if %cc% lss 10 set cc=0%cc%
echo Whirlpool (Hidden) = %hh%:%mm%:%ss%,%cc%
echo.

"c:\Program Files\VeraCrypt\veracrypt.exe" /dismount %mydriveletter% /silent /q

rem Get start time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "start=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Mount SHA-256 container (Normal)
"c:\Program Files\VeraCrypt\veracrypt.exe" /volume test.sha256.hc /hash sha256 /l %mydriveletter% /password test /q /silent /m ro

rem Get end time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "end=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Get elapsed time:
set /A elapsed=end-start

rem Show elapsed time:
set /A hh=elapsed/(60*60*100), rest=elapsed%%(60*60*100), mm=rest/(60*100), rest%%=60*100, ss=rest/100, cc=rest%%100
if %hh% lss 10 set hh=0%hh%
if %mm% lss 10 set mm=0%mm%
if %ss% lss 10 set ss=0%ss%
if %cc% lss 10 set cc=0%cc%
echo SHA-256 (Normal) = %hh%:%mm%:%ss%,%cc%

"c:\Program Files\VeraCrypt\veracrypt.exe" /dismount %mydriveletter% /silent /q

rem Get start time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "start=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Mount SHA-256 container (Hidden)
"c:\Program Files\VeraCrypt\veracrypt.exe" /volume test.sha256.hc /hash sha256 /l %mydriveletter% /password testhidden /q /silent /m ro

rem Get end time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "end=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Get elapsed time:
set /A elapsed=end-start

rem Show elapsed time:
set /A hh=elapsed/(60*60*100), rest=elapsed%%(60*60*100), mm=rest/(60*100), rest%%=60*100, ss=rest/100, cc=rest%%100
if %hh% lss 10 set hh=0%hh%
if %mm% lss 10 set mm=0%mm%
if %ss% lss 10 set ss=0%ss%
if %cc% lss 10 set cc=0%cc%
echo SHA-256 (Hidden) = %hh%:%mm%:%ss%,%cc%
echo.

"c:\Program Files\VeraCrypt\veracrypt.exe" /dismount %mydriveletter% /silent /q

rem Get start time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "start=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Mount RIPEMD-160 container (Normal)
"c:\Program Files\VeraCrypt\veracrypt.exe" /volume test.ripemd160.hc /hash ripemd160 /l %mydriveletter% /password test /q /silent /m ro

rem Get end time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "end=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Get elapsed time:
set /A elapsed=end-start

rem Show elapsed time:
set /A hh=elapsed/(60*60*100), rest=elapsed%%(60*60*100), mm=rest/(60*100), rest%%=60*100, ss=rest/100, cc=rest%%100
if %hh% lss 10 set hh=0%hh%
if %mm% lss 10 set mm=0%mm%
if %ss% lss 10 set ss=0%ss%
if %cc% lss 10 set cc=0%cc%
echo RIPEMD-160 (Normal) = %hh%:%mm%:%ss%,%cc%

"c:\Program Files\VeraCrypt\veracrypt.exe" /dismount %mydriveletter% /silent /q

rem Get start time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "start=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Mount RIPEMD-160 container (Hidden)
"c:\Program Files\VeraCrypt\veracrypt.exe" /volume test.ripemd160.hc /hash ripemd160 /l %mydriveletter% /password testhidden /q /silent /m ro

rem Get end time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "end=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Get elapsed time:
set /A elapsed=end-start

rem Show elapsed time:
set /A hh=elapsed/(60*60*100), rest=elapsed%%(60*60*100), mm=rest/(60*100), rest%%=60*100, ss=rest/100, cc=rest%%100
if %hh% lss 10 set hh=0%hh%
if %mm% lss 10 set mm=0%mm%
if %ss% lss 10 set ss=0%ss%
if %cc% lss 10 set cc=0%cc%
echo RIPEMD-160 (Hidden) = %hh%:%mm%:%ss%,%cc%
echo.

"c:\Program Files\VeraCrypt\veracrypt.exe" /dismount %mydriveletter% /silent /q

rem Get start time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "start=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Try to mount with a wrong password and PRF autodetection
"c:\Program Files\VeraCrypt\veracrypt.exe" /volume test.sha512.hc /l %mydriveletter% /password wrongpassword /q /silent /m ro

rem Get end time:
for /F "tokens=1-4 delims=:.," %%a in ("%time%") do (
   set /A "end=(((%%a*60)+1%%b %% 100)*60+1%%c %% 100)*100+1%%d %% 100"
)

rem Get elapsed time:
set /A elapsed=end-start

rem Show elapsed time:
set /A hh=elapsed/(60*60*100), rest=elapsed%%(60*60*100), mm=rest/(60*100), rest%%=60*100, ss=rest/100, cc=rest%%100
if %hh% lss 10 set hh=0%hh%
if %mm% lss 10 set mm=0%mm%
if %ss% lss 10 set ss=0%ss%
if %cc% lss 10 set cc=0%cc%
echo Wrong Password (PRF Auto-detection)= %hh%:%mm%:%ss%,%cc%
echo.


goto :exit

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

:exit
