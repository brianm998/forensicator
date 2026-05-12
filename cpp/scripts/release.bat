@echo off
setlocal enabledelayedexpansion

REM Usage: scripts\release.bat [--version VERSION]
set "VERSION="

:parse
if "%~1"=="" goto done
if /I "%~1"=="--version" (
    set "VERSION=%~2"
    shift
    shift
    goto parse
)
if /I "%~1"=="-h" goto help
if /I "%~1"=="--help" goto help
echo unknown option: %~1
exit /b 2

:help
echo usage: %0 [--version VERSION]
exit /b 0

:done
pushd "%~dp0\.."

if "%VERSION%"=="" (
    if exist VERSION (
        set /p VERSION=<VERSION
    ) else (
        set "VERSION=dev"
    )
)

set "OS=windows"
set "ARCH=%PROCESSOR_ARCHITECTURE%"
if /I "%ARCH%"=="AMD64" set "ARCH=x86_64"
if /I "%ARCH%"=="ARM64" set "ARCH=arm64"

set "BUILD_DIR=build-release"
set "DIST_DIR=dist"
if not exist %DIST_DIR% mkdir %DIST_DIR%

cmake -S . -B %BUILD_DIR% -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1
cmake --build %BUILD_DIR% --config Release --parallel
if errorlevel 1 exit /b 1

set "PKG=forensicator-%OS%-%ARCH%-%VERSION%"
set "STAGE=%BUILD_DIR%\%PKG%"
if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%\bin"
mkdir "%STAGE%\share\forensicator"
copy /Y "%BUILD_DIR%\Release\forensicator.exe" "%STAGE%\bin\" >nul
if errorlevel 1 copy /Y "%BUILD_DIR%\forensicator.exe" "%STAGE%\bin\" >nul
copy /Y "..\schema\forensicator.sql" "%STAGE%\share\forensicator\" >nul

powershell -NoLogo -Command "Compress-Archive -Path '%STAGE%\*' -DestinationPath '%DIST_DIR%\%PKG%.zip' -Force"
echo wrote %DIST_DIR%\%PKG%.zip
popd
endlocal
