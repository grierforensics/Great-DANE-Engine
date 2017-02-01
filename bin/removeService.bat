@echo off

set "DIRNAME=%~dp0"

>"%DIRNAME%/remove.log" (
    "%DIRNAME%/service.bat" remove
)
