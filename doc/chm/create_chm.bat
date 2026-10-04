PATH=%PATH%;C:\Program Files (x86)\HTML Help Workshop

set CHMBUILDPATH=%~dp0
cd %CHMBUILDPATH%\en

xcopy /E ..\..\html\en\* .

hhc VeraCrypt.hhp

del /F /Q *.html *.css *.jpg *.gif *.png *.svg *.js
rmdir /s /Q CompilingGuidelineWin

move /Y "VeraCrypt User Guide.chm" "..\VeraCrypt User Guide.chm"

cd %CHMBUILDPATH%\zh-cn

xcopy /E ..\..\html\zh-cn\* .

hhc VeraCrypt.zh-cn.hhp

del /F /Q *.html *.css *.jpg *.gif *.png *.svg *.js
rmdir /s /Q CompilingGuidelineWin

move /Y "VeraCrypt User Guide.zh-cn.chm" "..\VeraCrypt User Guide.zh-cn.chm"

cd %CHMBUILDPATH%\ru

xcopy /E ..\..\html\ru\* .

hhc VeraCrypt.ru.hhp

del /F /Q *.html *.css *.jpg *.gif *.png *.svg *.js
rmdir /s /Q CompilingGuidelineWin

move /Y "VeraCrypt User Guide.ru.chm" "..\VeraCrypt User Guide.ru.chm"

cd %CHMBUILDPATH%




