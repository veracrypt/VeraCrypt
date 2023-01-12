PATH=%PATH%;C:\Program Files (x86)\HTML Help Workshop

set CHMBUILDPATH=%~dp0
cd %CHMBUILDPATH%

xcopy /E ..\html\* .

hhc VeraCrypt.hhp

del /F /Q *.html *.css *.jpg *.gif *.png *.svg
rmdir /s /Q CompilingGuidelineWin ru
