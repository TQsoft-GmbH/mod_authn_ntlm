@echo off
setlocal enableextensions enabledelayedexpansion

	PowerShell -ExecutionPolicy RemoteSigned %~dp0\Get-Apache.ps1 -Arch %ARCHITECTURE% -DownloadPath %APPVEYOR_BUILD_FOLDER%

	xcopy %APPVEYOR_BUILD_FOLDER%\README.md %APPVEYOR_BUILD_FOLDER%\artifacts\ /y /f
	xcopy %APPVEYOR_BUILD_FOLDER%\copyright.txt %APPVEYOR_BUILD_FOLDER%\artifacts\ /y /f
	xcopy %APPVEYOR_BUILD_FOLDER%\CMakeLists.txt %APPVEYOR_BUILD_FOLDER%\artifacts\ /y /f
	xcopy %APPVEYOR_BUILD_FOLDER%\conf %APPVEYOR_BUILD_FOLDER%\artifacts\conf\ /y /f
	xcopy %APPVEYOR_BUILD_FOLDER%\src %APPVEYOR_BUILD_FOLDER%\artifacts\src\ /y /f

	if "%APPVEYOR_REPO_TAG_NAME%"=="" (
		set APPVEYOR_REPO_TAG_NAME=%APPVEYOR_REPO_BRANCH%-%APPVEYOR_REPO_COMMIT:~0,8%
		for /f "tokens=1-3* delims= " %%i in (src\mod_ntlm_version.h) do (
			if "%%j"=="MOD_NTLM_VERSION_MAJOR" (
				set MOD_NTLM_VERSION_MAJOR=%%k
			)
			if "%%j"=="MOD_NTLM_VERSION_MID" (
				set MOD_NTLM_VERSION_MID=%%k
			)
			if "%%j"=="MOD_NTLM_VERSION_MINOR" (
				set MOD_NTLM_VERSION_MINOR=%%k
			)
		)
		set MOD_NTL_VERSION=!MOD_NTLM_VERSION_MAJOR!.!MOD_NTLM_VERSION_MID!.!MOD_NTLM_VERSION_MINOR!
		set APPVEYOR_REPO_TAG_NAME=!MOD_NTL_VERSION!-!APPVEYOR_REPO_TAG_NAME!

		appveyor SetVariable -Name APPVEYOR_REPO_TAG_NAME -Value !APPVEYOR_REPO_TAG_NAME!
	)

endlocal
