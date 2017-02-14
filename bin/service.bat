rem Licensed to the Apache Software Foundation (ASF) under one or more
rem contributor license agreements.  See the NOTICE file distributed with
rem this work for additional information regarding copyright ownership.
rem The ASF licenses this file to You under the Apache License, Version 2.0
rem (the "License"); you may not use this file except in compliance with
rem the License.  You may obtain a copy of the License at
rem
rem     http://www.apache.org/licenses/LICENSE-2.0
rem
rem Unless required by applicable law or agreed to in writing, software
rem distributed under the License is distributed on an "AS IS" BASIS,
rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
rem See the License for the specific language governing permissions and
rem limitations under the License.

rem ---------------------------------------------------------------------------
rem NT Service Install/Uninstall script
rem
rem Options
rem install                Install the service using GreatDANEEngine as service name.
rem                        Service is installed using default settings.
rem remove                 Remove the service from the System.
rem
rem name        (optional) If the second argument is present it is considered
rem                        to be new service name
rem ---------------------------------------------------------------------------

@echo off

setlocal

set RETCODE=0
set "CURRENT_DIR=%cd%"
set "SELF=%~dp0%service.bat"

rem Relocate to Engine install directory
cd "%~dp0"
cd ..
set "GREATDANEENGINE_HOME=%cd%"

if exist "%GREATDANEENGINE_HOME%\bin\greatdaneengine.exe" goto okHome
echo The greatdaneengine.exe was not found...
echo The GREATDANEENGINE_HOME environment variable is not defined correctly.
echo This environment variable is needed to run this program
set RETCODE=1
goto end
:okHome
rem Make sure prerequisite environment variables are set
if not "%JAVA_HOME%" == "" goto gotJdkHome
if not "%JRE_HOME%" == "" goto gotJreHome
echo Neither the JAVA_HOME nor the JRE_HOME environment variable is defined
echo Service will try to guess them from the registry.
goto okJavaHome
:gotJreHome
if not exist "%JRE_HOME%\bin\java.exe" goto noJavaHome
if not exist "%JRE_HOME%\bin\javaw.exe" goto noJavaHome
goto okJavaHome
:gotJdkHome
if not exist "%JAVA_HOME%\jre\bin\java.exe" goto noJavaHome
if not exist "%JAVA_HOME%\jre\bin\javaw.exe" goto noJavaHome
if not exist "%JAVA_HOME%\bin\javac.exe" goto noJavaHome
if not "%JRE_HOME%" == "" goto okJavaHome
set "JRE_HOME=%JAVA_HOME%\jre"
goto okJavaHome
:noJavaHome
echo The JAVA_HOME environment variable is not defined correctly
echo This environment variable is needed to run this program
echo NB: JAVA_HOME should point to a JDK not a JRE
set RETCODE=2
goto end
:okJavaHome
if not "%GREATDANEENGINE_BASE%" == "" goto gotBase
set "GREATDANEENGINE_BASE=%GREATDANEENGINE_HOME%"
:gotBase

set "EXECUTABLE=%GREATDANEENGINE_HOME%\bin\greatdaneengine.exe"

rem Set default Service name
set SERVICE_NAME=GreatDANEEngine
set DISPLAYNAME=Grier Forensics %SERVICE_NAME%

rem Handle command line arguments
if "x%1x" == "xx" goto displayUsage
set SERVICE_CMD=%1
shift
if "x%1x" == "xx" goto checkServiceCmd
:checkUser
if "x%1x" == "x/userx" goto runAsUser
if "x%1x" == "x--userx" goto runAsUser
set SERVICE_NAME=%1
set DISPLAYNAME=Apache Tomcat @VERSION_MAJOR_MINOR@ %1
shift
if "x%1x" == "xx" goto checkServiceCmd
goto checkUser
:runAsUser
shift
if "x%1x" == "xx" goto displayUsage
set SERVICE_USER=%1
shift
runas /env /savecred /user:%SERVICE_USER% "%COMSPEC% /K \"%SELF%\" %SERVICE_CMD% %SERVICE_NAME%"
goto end
:checkServiceCmd
if /i %SERVICE_CMD% == install goto doInstall
if /i %SERVICE_CMD% == remove goto doRemove
if /i %SERVICE_CMD% == uninstall goto doRemove
if /i %SERVICE_CMD% == start goto doStart
if /i %SERVICE_CMD% == stop goto doStop
echo Unknown parameter "%SERVICE_CMD%"
:displayUsage
echo.
echo Usage: service.bat install/remove/start/stop [service_name] [/user username]
set RETCODE=42
goto end

:doRemove
rem Remove the service
echo Removing the service '%SERVICE_NAME%' ...
echo Using GREATDANEENGINE_BASE:    "%GREATDANEENGINE_BASE%"

"%EXECUTABLE%" //DS//%SERVICE_NAME% ^
    --LogPath "%GREATDANEENGINE_BASE%\logs"
if not errorlevel 1 goto removed
echo Failed to remove '%SERVICE_NAME%' service
RETCODE=3
goto end
:removed
echo The service '%SERVICE_NAME%' has been removed
goto end

:doStart
rem Start the service
echo Starting the service '%SERVICE_NAME%' ...
echo Using GREATDANEENGINE_BASE:    "%GREATDANEENGINE_BASE%"

"%EXECUTABLE%" //ES//%SERVICE_NAME% ^
    --LogPath "%GREATDANEENGINE_BASE%\logs"
if not errorlevel 1 goto started
echo Failed to start '%SERVICE_NAME%' service
RETCODE=4
goto end
:started
echo The service '%SERVICE_NAME%' has been started
goto end

:doStop
rem Stop the service
echo Stopping the service '%SERVICE_NAME%' ...
echo Using GREATDANEENGINE_BASE:    "%GREATDANEENGINE_BASE%"

"%EXECUTABLE%" //SS//%SERVICE_NAME% ^
    --LogPath "%GREATDANEENGINE_BASE%\logs"
if not errorlevel 1 goto stopped
echo Failed to stop '%SERVICE_NAME%' service
RETCODE=5
goto end
:stopped
echo The service '%SERVICE_NAME%' has been stopped
goto end

:doInstall
rem Install the service
echo Installing the service '%SERVICE_NAME%' ...
echo Using GREATDANEENGINE_HOME:    "%GREATDANEENGINE_HOME%"
echo Using GREATDANEENGINE_BASE:    "%GREATDANEENGINE_BASE%"
echo Using JAVA_HOME:        "%JAVA_HOME%"
echo Using JRE_HOME:         "%JRE_HOME%"

rem Try to use the server jvm
set "JVM=%JRE_HOME%\bin\server\jvm.dll"
if exist "%JVM%" goto foundJvm
rem Try to use the client jvm
set "JVM=%JRE_HOME%\bin\client\jvm.dll"
if exist "%JVM%" goto foundJvm
echo Warning: Neither 'server' nor 'client' jvm.dll was found at JRE_HOME.
set JVM=auto
:foundJvm
echo Using JVM:              "%JVM%"

set "CLASSPATH=%GREATDANEENGINE_HOME%\lib\*;"

"%EXECUTABLE%" //IS//%SERVICE_NAME% ^
    --Description "Great DANE Engine 1.0 - grierforensics.com" ^
    --DisplayName "%DISPLAYNAME%" ^
    --Install "%EXECUTABLE%" ^
    --Startup auto ^
    --LogPath "%GREATDANEENGINE_BASE%\logs" ^
    --StdOutput auto ^
    --StdError auto ^
    --Classpath "%CLASSPATH%" ^
    --Jvm "%JVM%" ^
    --StartMode jvm ^
    --StartPath "%GREATDANEENGINE_HOME%" ^
    --StartClass com.grierforensics.greatdane.Daemon ^
    --StartParams start ^
    --StopMode jvm ^
    --StopPath "%GREATDANEENGINE_HOME%" ^
    --StopClass com.grierforensics.greatdane.Daemon ^
    --StopParams stop ^
    --JvmMs 128 ^
    --JvmMx 256

rem --JvmOptions "-Dcatalina.home=%GREATDANEENGINE_HOME%;-Dcatalina.base=%GREATDANEENGINE_BASE%;-Djava.endorsed.dirs=%GREATDANEENGINE_HOME%\endorsed;-Djava.io.tmpdir=%GREATDANEENGINE_BASE%\temp;-Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager;-Djava.util.logging.config.file=%GREATDANEENGINE_BASE%\conf\logging.properties" ^
if not errorlevel 1 goto installed
echo Failed to install '%SERVICE_NAME%' service
RETCODE=6
goto end
:installed
echo The service '%SERVICE_NAME%' has been installed.

:end
cd "%CURRENT_DIR%"
exit /b %RETCODE%
