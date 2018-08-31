<#
	.SYNOPSIS
	PowerShell script to install Apache

	.LINK
	https://github.com/fawno/WAMP-Tools/tree/PowerShell

	.LINK
	https://lab.fawno.com
#>

	Param (
		[ValidateSet("x86", "x64", "X86", "X64")] [string] $Arch = "x64",
		[string] $DownloadPath = ".."
	)

	$Arch = $Arch.ToLower()

	$ApacheLounge = "https://www.apachelounge.com/download/"

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	Write-Output "Checking for downloadable Apache versions..."

	$Releases = @()

	$DownloadsPage = Invoke-WebRequest $ApacheLounge -UserAgent ""
	$DownloadsPage.Links | Where-Object { $_.innerText -match "^httpd-([\d\.]+)-(win\d+)-(VC\d+).zip$" } | ForEach-Object {
		$Matches[2] = $Matches[2].ToLower().Replace("win32", "x86").Replace("win64", "x64")
		$Releases += @{
			DownloadFile = $Matches[0];
			Version = New-Object -TypeName System.Version($Matches[1]);
			VC = $Matches[3];
			VCVersion = "$($Matches[3])_$($Matches[2])";
			Architecture = $Matches[2];
			DownloadUrl = $_.href;
		}
	}


	$Release = $Releases | Where-Object { $_.Architecture -eq $Arch } | Sort-Object -Descending { $_.Version } | Select-Object -First 1

	if (!$Release) {
		throw "Unable to find an installable version of $Arch Apache $Version. Check that the version specified is correct."
	}

	$ApacheDownloadUri = $Release.DownloadUrl
	$ApacheFileName = [Uri]::new([Uri]$ApacheDownloadUri).Segments[-1]
	$ApacheDownloadFile = "$DownloadPath\$ApacheFileName"

	if (!(Test-Path -Path "$DownloadPath\bin\httpd.exe" )) {
		if (!(Test-Path -Path "$DownloadPath" )) {
			New-Item -ItemType Directory -Force -Path $DownloadPath | Out-Null
		}

		if (!(Test-Path -Path $ApacheDownloadFile )) {
			Write-Output "Downloading Apache $($Release.Version) ($ApacheFileName)..."
			try {
				Start-BitsTransfer -Source $ApacheDownloadUri -Destination $ApacheDownloadFile
			} catch {
				throw "Unable to download Apache from: $ApacheDownloadUri"
			}
		}

		if ((Test-Path -Path $ApacheDownloadFile )) {
			try {
				Write-Output "Extracting Apache $($Release.Version) ($ApacheFileName) to: $DownloadPath"
				Expand-Archive -LiteralPath $ApacheDownloadFile -DestinationPath $DownloadPath -ErrorAction Stop
			} catch {
				throw "Unable to extract Apache from ZIP"
			}
			Remove-Item $ApacheDownloadFile -Force -ErrorAction SilentlyContinue | Out-Null
		}
	}
