#
# This script uses Rustdesk2.toml copied in C:\data
#
$rustdesk_version 	= "1.2.3-2"
$rustdesk_pw 		= "password"

$download_uri 		= "https://github.com/rustdesk/rustdesk/releases/download/" `
						+ $rustdesk_version + "/rustdesk-" + $rustdesk_version + "-x86_64.exe"

$ErrorActionPreference= 'silentlycontinue'
#Run as administrator and stays in the current directory
if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        Start-Process PowerShell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        Exit;
    }
}

If (!(Test-Path $env:Temp)) {
  New-Item -ItemType Directory -Force -Path $env:Temp > null
}

If (!(Test-Path "$env:ProgramFiles\Rustdesk\RustDesk.exe")) {

	$ErrorActionPreference= 'silentlycontinue'

	If (!(Test-Path c:\Temp)) {
	  New-Item -ItemType Directory -Force -Path c:\Temp > null
	}

	cd c:\Temp

	powershell Invoke-WebRequest $download_uri -Outfile "rustdesk.exe"
	Start-Process .\rustdesk.exe --silent-install -wait

	$ServiceName = 'Rustdesk'
	$arrService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

	if ($arrService -eq $null) {
		Start-Sleep -seconds 20
	}

	while ($arrService.Status -ne 'Running') {
		Start-Service $ServiceName
		Start-Sleep -seconds 5
		$arrService.Refresh()
	}

	net stop rustdesk

	$username = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).Split('\')[1]
	Remove-Item C:\Users\$username\AppData\Roaming\RustDesk\config\RustDesk2.toml -Force
	Remove-Item C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml -Force
	Copy-Item "C:\Data\RustDesk2.toml" -Destination "C:\Users\$username\AppData\Roaming\RustDesk\config" -Force
	Move-Item -Path "C:\Data\RustDesk2.toml" -Destination "C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config" -Force

	net start rustdesk

	Start-Process "$env:ProgramFiles\RustDesk\RustDesk.exe"  -argumentlist "--password $rustdesk_pw" -wait

	net stop rustdesk > null
	$ProcessActive = Get-Process rustdesk -ErrorAction SilentlyContinue
	if($ProcessActive -ne $null) {
		stop-process -ProcessName rustdesk -Force
	}

	Start-Process "$env:ProgramFiles\RustDesk\RustDesk.exe" "--password $rustdesk_pw" -wait

	net start rustdesk > null

	cd $env:ProgramFiles\RustDesk\
	$rustdesk_id = (.\RustDesk.exe --get-id | out-host)

	Write-Output "RustDesk ID is: $rustdesk_id"
	Write-Output "RustDesk Password is: $rustdesk_pw"

	Stop-Process -Name RustDesk -Force > null
	Start-Service -Name RustDesk > null
	
}
