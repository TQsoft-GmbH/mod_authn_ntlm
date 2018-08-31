@echo off
setlocal enableextensions enabledelayedexpansion
	cd /d %APPVEYOR_BUILD_FOLDER%

	if not exist "Apache24\bin\httpd.exe" (
		echo Apache24 not found
		exit /b 3
	)

	if "%ARCHITECTURE%"=="x64" (
		set GENERATOR="Visual Studio 15 2017 Win64"
	)

	if "%ARCHITECTURE%"=="x86" (
		set GENERATOR="Visual Studio 15 2017"
	)

	mkdir %APPVEYOR_BUILD_FOLDER%\build

	set CMAKE_BUILD_TYPE=Release
	cmd /c %APPVEYOR_BUILD_FOLDER%\appveyor\build-task.cmd

	set CMAKE_BUILD_TYPE=Debug
	cmd /c %APPVEYOR_BUILD_FOLDER%\appveyor\build-task.cmd
endlocal
