@echo off

set "DIRNAME=%~dp0"

>"%DIRNAME%/install.log" (
    "%DIRNAME%/service.bat" install
    "%DIRNAME%/service.bat" start
)
