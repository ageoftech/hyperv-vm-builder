<#
--------------------------------------------------------------------------------------
 Script for provisioning a Windows VM from a template

    -Create     :   creates the VM
    -Destroy    :   deletes the VM and associated files
    -AD         :   joins the domain with -Create
                   removes from domain with -Destroy
    -Nb         :   desired number of VMs

- if a VM is using the source VHD, it must be stopped and its snapshots deleted

- $ConfigName is the name of the property folder used to define
  all the creation parameters

- base class VMBuilder with 2 subclasses:
    -- UbuntuVMBuilder
    -- WindowsVMBuilder
    
    -- the static method GetBuilders returns instances suited to the template's OS
--------------------------------------------------------------------------------------
#>
param
(
	[string] $ConfigName,
	[int]	 $Nb = 1,
	[switch] $AD = $false,
	[switch] $Create = $true,
	[switch] $Destroy
)

# -------------------------------------------------------------------------------
# MAIN MAIN MAIN
# -------------------------------------------------------------------------------

$Builders = [VMBuilder]::GetBuilders($ConfigName, $AD, $Nb)
try {
	if ($Destroy) {
		throw 'DESTRUCTION'
	} 
	$Builders | ForEach-Object -Process { $_.Create() } 
} catch {
	$Builders | ForEach-Object -Process { $_.Destroy() }
}
   

# -------------------------------------------------------------------------------
# CLASSES
# -------------------------------------------------------------------------------

class VMBuilder {
	static [Hashtable] $MainConfig

	[string]	$ConfigName
	[Hashtable]	$Config
	[bool] 		$AD
	[string] 	$VMHostname
	[string] 	$VMName
	[string] 	$VMPath			
	[string] 	$VMHost 	
	[string] 	$VMUNCPath 		
	[string] 	$VMLocalPath
	[string]	$VMInfos
	[string]	$LogFile

	# -------------------------------------------------------------------------------
	# Creates a builder list from VM template OS 
	# -------------------------------------------------------------------------------
	static [VMBuilder[]] GetBuilders([string]$ConfigName, [bool]$AD, [int]$Nb) {
		[VMBuilder]::ReadConfig($ConfigName)			
		[VMBuilder]::GetAuthTokens($AD)
		$Builders = @()
		$Many = ($Nb -gt 1)
		$OSWindows = [VMBuilder]::IsTemplateOSWindows()
		while ($Nb -gt 0) {
			if ($OSWindows) {
				$Builder = New-Object WindowsVMBuilder
			} else {
				$Builder = New-Object UbuntuVMBuilder
			}
			$Conf = [VMBuilder]::MainConfig.Clone()
			if ($Many) {
				$Conf.'VM.Name' 		+= ('-' + $Nb)
				$Conf.'VM.Hostname' 	+= ('-' + $Nb)
			}
			$Builder.Init($ConfigName, $Conf, $AD)
			$Builders += $Builder
			$Nb = $Nb - 1
		}
		return $Builders
	}
		
	# -------------------------------------------------------------------------------
	# TO REDEFINE by subclasses
	# -------------------------------------------------------------------------------
	
	# first putty command (to init ssh)
	[string] GetFirstPuttyCommand() {
		return 'echo 1'
	}

	# folder path to receive files in $VM/data
	[string] GetVMDataDir() {
		return $this.Config.'VM.BaseDir'
	}

	# updates script name (ie update.sh or update.ps1)
	[string] GetVMUpdateScript() {
		throw("TO REDEFINE")
	}
	
	# info script name to get VM informations afer full install
	[string] GetVMInfoScript() {
		throw("TO REDEFINE")
	}
	
	# runs a script on a VM
	[string] ExecScriptVM([string]$HostName,[string[]]$Script) {
		throw("TO REDEFINE")
	}
	
	# prepares AD join 
	[string] PreJoinAD([string] $IPv4) {
		return $IPv4
	}
	
	# builds an infos string
	[string] ToString() {
		$Info = $this.GetType().ToString() + ' ' + $this.VMName + ' <- ' + $this.Config.'Template.VMName'
		$Info += ([Environment]::NewLine) + "VMHostname: " 		+ $this.VMHostname
		$Info += ([Environment]::NewLine) + "VMName: " 			+ $this.VMName
		$Info += ([Environment]::NewLine) + "VMPath: " 			+ $this.VMPath
		$Info += ([Environment]::NewLine) + "VMHost: " 			+ $this.VMHost
		$Info += ([Environment]::NewLine) + "VMUNCPath: " 		+ $this.VMUNCPath
		$Info += ([Environment]::NewLine) + "VMLocalPath: " 	+ $this.VMLocalPath
		$Info += ([Environment]::NewLine) + "VMInfos: " 		+ $this.VMInfos
		return $Info
	}
		
	# -------------------------------------------------------------------------------
	# config file (vm.properties) reading
	# -------------------------------------------------------------------------------
	static [void] ReadConfig([string]$ConfigName) {
		$ConfigFile = ".\" + $ConfigName + "\vm.properties"
		[VMBuilder]::MainConfig = ConvertFrom-StringData (Get-Content $ConfigFile -Raw)
		#
		# if VM.Name and VM.Hostname are not set, we use the name of the folder containing params
		#
		if ([VMBuilder]::MainConfig.'VM.Name'.Length -eq 0) {
			[VMBuilder]::MainConfig.'VM.Name' = $ConfigName 
		}		
		if ([VMBuilder]::MainConfig.'VM.Hostname'.Length -eq 0) {
			[VMBuilder]::MainConfig.'VM.Hostname' = $ConfigName 
		}		
		[VMBuilder]::MainConfig | Out-Host
	}
	
	# -------------------------------------------------------------------------------
	# checks if template OS is windows
	# -------------------------------------------------------------------------------
	static [bool] IsTemplateOSWindows() {
		$HHost = [VMBuilder]::MainConfig.'Template.HyperVHost'
		$VM = [VMBuilder]::MainConfig.'Template.VMName'
		$Fw = Get-VMFirmware -ComputerName $HHost -VMName $VM
		$Fw | Out-Host
		# WARNING SecureBootTemplate may contain 'Windows' even in case of Linux OS !
		return ($Fw.SecureBoot -eq 'On') -and ($Fw.SecureBootTemplate -like '*Windows*')
	}
	
	# -------------------------------------------------------------------------------
	# AD authentication
	# -------------------------------------------------------------------------------
	static [bool] TestADAuthentication ([string]$Username, [string]$Password) {    
		return (New-Object DirectoryServices.DirectoryEntry "",$Username,$Password).psbase.name -ne $null
	}

	# -------------------------------------------------------------------------------
	# gets login and password from keyboard if not defined in vm.properties
	# -------------------------------------------------------------------------------
	static [void] GetAuthTokens([bool]$AD) {
		if ($AD) {
			# reads login/password of AD admin
			if ([VMBuilder]::MainConfig.'Domain.Admin'.Length -eq 0) {
				[VMBuilder]::MainConfig.'Domain.Admin' = Read-Host "Login admin domaine" 
			}
			if ([VMBuilder]::MainConfig.'Domain.Password'.Length -eq 0) {
				$Msg = "Domain admin password " + [VMBuilder]::MainConfig.'Domain.Admin'
				$SecureText	= Read-Host $Msg -AsSecureString
				[VMBuilder]::MainConfig.'Domain.Password' = [Runtime.InteropServices.Marshal]::PtrToStringAuto( `
									[Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureText) `
								)
			}

			# checks login/password of AD admin
			if (-not ([VMBuilder]::TestADAuthentication([VMBuilder]::MainConfig.'Domain.Admin',[VMBuilder]::MainConfig.'Domain.Password'))) {
				Write-Host 'Invalid AD credential'
				exit
			}
		}
		
		# reads login/password of template user if needed 
		if ([VMBuilder]::MainConfig.'Template.Login'.Length -eq 0) {
			[VMBuilder]::MainConfig.'Template.Login' = Read-Host "Template login"
		}
		if ([VMBuilder]::MainConfig.'Template.Password'.Length -eq 0) {
			$Msg = "Template " + [VMBuilder]::MainConfig.'Template.Login' + " password"
			$SecureText	= Read-Host $Msg -AsSecureString
			[VMBuilder]::MainConfig.'Template.Password' = [Runtime.InteropServices.Marshal]::PtrToStringAuto( `
										[Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureText) `
									)
		}
	}

	# -------------------------------------------------------------------------------
	# Log
	# -------------------------------------------------------------------------------
	[void] Log([string[]]$Msg) {
		$Val = ""
		foreach ($Str in $Msg) {
			$Val += $Str + " "
		}
		Add-content $this.Logfile -value $Val
		Write-Host $Val	
	}
	
	# -------------------------------------------------------------------------------
	# utilities to get hostname from UNC path and vice-versa
	# -------------------------------------------------------------------------------
	[string] GetHostNameFromUNC ([string]$UNCPath) {
		$UNCPath -match '\\\\(.*?)\\' | Out-Null
		if ($Matches.Count -ge 2) {
			return $Matches[1]
		} else {
			return $null
		}
	}

	[string] GetLocalPathFromUNC ([string]$UNCPath) {
		$Drive = [System.IO.Path]::GetPathRoot($UNCPath)
		$Dumps = $UNCPath.Substring($Drive.Length)
		$Drive = $Drive.Substring($Drive.LastIndexOf('\') + 1).Replace('$',':')
		return "$Drive$Dumps"
	}

	[string] ConvertToUNCPath ([string]$Path, [string]$HostName) {
		$PathRoot = [System.IO.Path]::GetPathRoot($Path)
		return "\\$($HostName)$(($Path).Replace($PathRoot, "\$($Path[0])$\"))"
	}

	# -------------------------------------------------------------------------------
	# builds a script file from strings containing shell commands
	# -------------------------------------------------------------------------------
	[void] CreateScriptFile([string]$Path, [string[]]$Script) {
		$Val = ""
		foreach ($Line in $Script) {
			$Val += $Line
			$Val += ([Environment]::NewLine)
		}
		Set-content $Path -NoNewLine -Value $Val
	}

	# -------------------------------------------------------------------------------
	# attemps to run a command on remote host with putty
	# so hostname will ne stored in ssh cache
	# -------------------------------------------------------------------------------
	[void] CheckRemoteHost([string]$HostName) {
		$Target = $this.Config.'Template.Login' + '@' + $HostName	
		echo y | plink $Target -pw $this.Config.'Template.Password' $this.GetFirstPuttyCommand()
		$this.Log("")
	}

	# -------------------------------------------------------------------------------
	# sends a local file on host (VM)
	# -------------------------------------------------------------------------------
	[void] CopyOnVM([string]$HostName,[string]$LocalPath,[string]$RemotePath) {
		$Target = $this.Config.'Template.Login' + '@' + $HostName + ':' + $RemotePath
		echo $this.Config.'Template.Password' | pscp $LocalPath $Target >> $this.LogFile
	}

	# -------------------------------------------------------------------------------
	# runs scipt on VM 
	# -------------------------------------------------------------------------------
	[string] CopyAndExecScriptVM([string]$HostName,[string]$ScriptName) {
		# reads script
		[string[]] $Script = Get-Content $ScriptName
		# run
		return $this.ExecScriptVM($HostName, $Script)
	}
	
	# -------------------------------------------------------------------------------
	# waits VM start
	# -------------------------------------------------------------------------------
	[void] WaitForVM() {
		while ((Get-VM -Name $this.VMName -ComputerName $this.VMHost).HeartBeat -notmatch 'Ok') { 
			Start-Sleep -s 2 
		}
	}

	# -------------------------------------------------------------------------------
	# reboot VM
	# -------------------------------------------------------------------------------
	[string] RebootVM() {
		$this.Log(@("Reboot ", $this.VMName, "@", $this.VMHost))
		Stop-VM -Name $this.VMName -ComputerName $this.VMHost 
		Start-VM -Name $this.VMName -ComputerName $this.VMHost 
		$this.WaitForVM()
		$IP =  $this.GetIPv4()
		$this.Log(@($this.VMName, "->", $IP))
		return $IP
	}

	# -------------------------------------------------------------------------------
	# waits to get @IP from VM
	# -------------------------------------------------------------------------------
	[string] GetIPv4() {
		$this.WaitForVM()
		[string[]] $IP = $null
		do {
			$IP = (Get-VMNetworkAdapter -ComputerName $this.VMHost -VMName $this.VMName).IPAddresses | ?{$_ -match '\.'}
			Start-Sleep -s 2 
		} while ($IP.Length -ne 1) # to remove 169.254.X.X which comes sometimes
		return $IP
	}

	# -------------------------------------------------------------------------------
	# init config & authentication
	# -------------------------------------------------------------------------------
	[void] Init([string]$ConfigName, [Hashtable]$Config, [bool]$AD) {
		$this.ConfigName 	= $ConfigName
		$this.AD 			= $AD
		$this.Config 		= $Config	
		$this.VMHostname 	= $this.Config.'VM.Hostname'
		$this.VMName 		= $this.Config.'VM.Name'
		$this.VMPath		= $this.Config[$this.Config.'VM.Path']
		$this.VMHost 		= $this.GetHostNameFromUNC($this.VMPath)
		$this.VMUNCPath 	= $this.VMPath 
		$this.VMLocalPath 	= $this.GetLocalPathFromUNC($this.VMUNCPath)
		$this.VMInfos		= $this.ConfigName + '\logs\' + $this.VMName + '-infos.txt'
		$CurrentDate 		= Get-Date -Format "dd-MM-yyyy-HH-mm"
		$this.Logfile 		= $this.ConfigName + '\logs\install-' + $CurrentDate + ".txt"


		$null > $this.VMInfos
		$null > $this.LogFile
		
		$this.Log("------------------------------------------------------------")
		$this.Log(@($this))
		$this.Log("------------------------------------------------------------")
	}
	
	# -------------------------------------------------------------------------------
	# creates VM
	# -------------------------------------------------------------------------------
	[void] InitVM() {
		# creation 1st step
		$this.Log("VM creation")
		$CreatedVM = New-VM `
							-ComputerName $this.VMHost `
							-Name $this.VMName `
							-Path $this.VMLocalPath `
							-NoVHD `
							-Generation 2 `
							-MemoryStartupBytes 4GB `
							-SwitchName $this.Config.'VM.HyperVSwitch' `
						>> $this.LogFile

		# memory and CPU					
		Set-VM `
				-ComputerName $this.VMHost `
				-Name $this.VMName `
				-ProcessorCount $this.Config.'VM.ProcessorCount' `
				-DynamicMemory `
			>> $this.LogFile
			
		#if ($this.Config.'VM.MaxMemory' -ne '') {
		#	Set-VM `
		#			-ComputerName $this.VMHost `
		#			-Name $this.VMName `
		#			-MemoryMaximumBytes $this.Config.'VM.MaxMemory' `
		#		>> $this.LogFile
		#}
	}
	
	# -------------------------------------------------------------------------------
	# copies template VHD to create VM own disk
	# -------------------------------------------------------------------------------
	[void] CreateVMDisk() {
		$this.Log("Template disk copy")
		$SourceVHD = Get-VMHardDiskDrive `
							-VMName $this.Config.'Template.VMName' `
							-ComputerName $this.Config.'Template.HyperVHost'
		$SourceVHDPath = Split-Path -Path $SourceVHD[0].Path -Parent					
		$SourcePath = $this.ConvertToUNCPath($SourceVHDPath, $this.Config.'Template.HyperVHost')
		$DestPath 	= $this.VMUNCPath + '\' + $this.VMName
		$VHD		= Split-Path -Path $SourceVHD[0].Path -Leaf

		# checks VM state
		$VM = Get-VM -ComputerName $this.Config.'Template.HyperVHost' -Name $this.Config.'Template.VMName'
		if ($VM.State -eq "On") {
			Stop-VM -ComputerName $this.Config.'Template.HyperVHost' -Name $this.Config.'Template.VMName' 
		}
		# VHD copy
		robocopy $SourcePath $DestPath $VHD
		# restore VM state after copy
		if ($VM.State -eq "On") {
			Start-VM -ComputerName $this.Config.'Template.HyperVHost' -Name $this.Config.'Template.VMName' 
		}
		# adds VHD to VM
		$DestVHD = $this.VMLocalPath + '\' + $this.VMName + '\' + $VHD
		Add-VMHardDiskDrive `
				-ComputerName $this.VMHost `
				-VMName $this.VMName `
				-Path $DestVHD 
		
		Get-VMHardDiskDrive -ComputerName $this.VMHost -VMName $this.VMName >> $this.LogFile		
	}
	
	# -------------------------------------------------------------------------------
	# boot disk setup
	# -------------------------------------------------------------------------------
	[void] ConfigureVMDisk() {
		$this.Log("Boot disk setup")
		$BootDrive = Get-VMHardDiskDrive `
							-ComputerName $this.VMHost `
							-VMName $this.VMName
					
		$TemplateVMFirmware = Get-VMFirmware `
								-ComputerName $this.Config.'Template.HyperVHost' `
								-VMName $this.Config.'Template.VMName' 

		# secure boot setup	
		if ($TemplateVMFirmware.SecureBoot -eq 'On') {		
			Set-VMFirmware `
				-ComputerName $this.VMHost `
				-VMName $this.VMName `
				-FirstBootDevice $BootDrive `
				-EnableSecureBoot $TemplateVMFirmware.SecureBoot `
				-SecureBootTemplate $TemplateVMFirmware.SecureBootTemplate
		} else {
			Set-VMFirmware `
				-ComputerName $this.VMHost `
				-VMName $this.VMName `
				-FirstBootDevice $BootDrive `
				-EnableSecureBoot $TemplateVMFirmware.SecureBoot 
		}			
			
		Get-VMFirmware -ComputerName $this.VMHost -VMName $this.VMName >> $this.LogFile
	}
	
	# -------------------------------------------------------------------------------
	# integration services setup (mandatory for network)
	# -------------------------------------------------------------------------------
	[void] ConfigureIntegration() {
		$this.Log("Integration services setup")
		Enable-VMIntegrationService `
				-ComputerName $this.VMHost `
				-VMName $this.VMName `
				-Name `
					"Shutdown", `
					"VSS", `
					"Guest Service Interface", `
					"Heartbeat", `
					"Key-Value Pair Exchange", `
					"Time Synchronization" `
			>> $this.LogFile
	}

	# -------------------------------------------------------------------------------
	# net adapter setup
	# -------------------------------------------------------------------------------
	[void] ConfigureNetSwitch() {
		$this.Log("Network setup")
		# VLAN
		if ($this.Config.'VM.VLan' -eq '') {
			Get-VM -ComputerName $this.VMHost -VMName $this.VMName `
				| Set-VMNetworkAdapterVlan -Untagged 
		} else {
			Get-VM -ComputerName $this.VMHost -VMName $this.VMName `
				| Set-VMNetworkAdapterVlan -Access -VlanId $this.Config.'VM.VLan' 
		}
		if ($this.Config.'VM.MacAddress' -ne '') {
			Get-VM -ComputerName $this.VMHost -VMName $this.VMName `
				| Set-VMNetworkAdapter -StaticMacAddress $this.Config.'VM.MacAddress' 
		} 
		#SR-IOV -> difficulté pour avoir une @IP ?
		#Get-VM -ComputerName $this.VMHost -VMName $this.VMName `
		#		| Set-VMNetworkAdapter -IovInterruptModeration Adaptive -IovWeight 50
	}
	
	# -------------------------------------------------------------------------------
	# VM secure start setup
	# -------------------------------------------------------------------------------
	[void] ConfigureVMSecurity() {
		$this.Log("VM secure start setup")
		$TemplateSecurity = Get-VMSecurity `
								-ComputerName $this.Config.'Template.HyperVHost' `
								-VMName $this.Config.'Template.VMName' 
		
		$this.Log("template secure start")
		$TemplateSecurity >> $this.LogFile
		
		if ($TemplateSecurity.TpmEnabled -eq $true) {
			# gets template TPM
			$KeyProtector = Get-VMKeyProtector `
								-ComputerName $this.Config.'Template.HyperVHost' `
								-VMName $this.Config.'Template.VMName'
				
			# sets VM TPM
			Set-VMKeyProtector `
				-ComputerName $this.VMHost `
				-VMName $this.VMName `
				-KeyProtector $KeyProtector >> $this.LogFile
			
			# activates VM TPM
			Enable-VMTPM `
				-ComputerName $this.VMHost `
				-VMName $this.VMName >> $this.LogFile
		}
	}
	
	# -------------------------------------------------------------------------------
	# CREATION
	# -------------------------------------------------------------------------------	
	[void] Create() {
		$this.InitVM()
		$this.CreateVMDisk()
		$this.ConfigureVMDisk()
		$this.ConfigureIntegration()
		$this.ConfigureNetSwitch()
		$this.ConfigureVMSecurity()
		
		$this.Log("VM start, wait for @IP")
		# VM start, wait for @IP
		Start-VM -Name $this.VMName -ComputerName $this.VMHost 
		$IPv4 = $this.GetIPv4()
		$this.Log($IPv4)

		$this.CheckRemoteHost($IPv4)
		# update 
		$UpdateScript = $this.ConfigName + '\' + $this.GetVMUpdateScript()
		if (Test-Path $UpdateScript) {
			$this.Log("Initial setup")
			$this.CopyAndExecScriptVM($IPv4, $UpdateScript)
			$IPv4 = $this.RebootVM()
		} else {
			$this.Log("update script missing")
		}
		
		# VM renaming and AD join if option activated
		if ($this.AD) {
			$IPv4 = $this.PreJoinAD($IPv4);
			$this.Log("AD join script")
			$Script = $this.BuildJoinADScript()
		} else {
			$this.Log("Renaming script")
			$Script = $this.BuildRenameVMScript()
		}
		$this.ExecScriptVM($IPv4,$Script)
		$IPv4 = $this.RebootVM()
		
		# copies files in /data
		$DataDir = $this.ConfigName + '\data'
		$this.Log(@("Files copied in ", $DataDir))
		if (Test-Path $DataDir) {
			foreach ($Data in (Get-ChildItem -Path $DataDir)) {
				$DataPath = $DataDir + '\' + $Data
				$this.Log(@("copy ", $DataPath))
				$this.CopyOnVM($IPv4, $DataPath, $this.GetVMDataDir())
			}
		}	
		# optional installs 
		$ScriptDir = $this.ConfigName + '\scripts' 
		$this.Log(@("Post-installations", $ScriptDir))
		if (Test-Path $ScriptDir) {
			foreach ($Script in (Get-ChildItem -Path $ScriptDir | Sort-Object)) {
				$this.CheckRemoteHost($IPv4)
				$ScriptName = $ScriptDir + '\' + $Script
				$this.Log(@("Script ", $ScriptName))
				$this.CopyAndExecScriptVM($IPv4, $ScriptName)
				$IPv4 = $this.RebootVM()
			}
		}
		# final update
		$this.Log("Final update")
		if (Test-Path $UpdateScript) {
			$this.CopyAndExecScriptVM($IPv4, $UpdateScript)
			$IPv4 = $this.RebootVM()
		}
		
		$vm = Get-VM -ComputerName $this.VMHost -Name $this.VMName
		$vm	>> $this.LogFile	
		
		# gets informations: ID Anydesk, software releases, ... 
		$this.Log("VM installations infos")
		$InfoScript = $this.ConfigName + '\' + $this.GetVMInfoScript()
		if (Test-Path $InfoScript) {
			$Res = $this.CopyAndExecScriptVM($IPv4, $InfoScript) 
			$Res | Out-File $this.VMInfos -Append
		}

	}
	
	# -------------------------------------------------------------------------------
	# DESTRUCTION
	# cleanup if problem occurs
	# - stop + VM delete
	# - VHD remove
	# - AD unjoin
	# -------------------------------------------------------------------------------
	[void] Destroy() {
		# checks VM state ans starts if needed
		$VM = Get-VM -ComputerName $this.VMHost -Name $this.VMName
		if ($VM.State -eq "Off") {
			Start-VM -Name $this.VMName -ComputerName $this.VMHost 
		}
		$IPv4 = $this.GetIPv4()
		$this.Log('------------------------------------------------------------------------------------------------')
		$this.Log(@('VM DESTRUCTION', $IPv4, 'VHD->', $this.VMLocalPath + '\' + $this.VMName))
		if ($this.AD) {
			$this.Log(@('AD leave', $this.Config.'Domain.Name'))
		} else {
			$this.Log("no AD leave")
		}
		$this.Log('------------------------------------------------------------------------------------------------')
		$this.CheckRemoteHost($IPv4)
		if ($this.AD) {
			$Script = $this.BuildLeaveADScript()
			$this.ExecScriptVM($IPv4,$Script)
		}
		$IPv4 = $this.RebootVM()
		Stop-VM -Name $this.VMName -ComputerName $this.VMHost -Force		
		Remove-VM -Name $this.VMName -ComputerName $this.VMHost -Force		
		Remove-Item -Recurse -Force -Path ($this.VMUNCPath + '\' + $this.VMName)	
	}

}

# -------------------------------------------------------------------------------
# UBUNTU
# -------------------------------------------------------------------------------
class UbuntuVMBuilder : VMBuilder {
	
	[string] GetFirstPuttyCommand() {
		return 'date'
	}
		
	[string] GetVMUpdateScript() {
		return "update.sh"
	}
	
	[string] GetVMInfoScript() {
		return "get-infos.sh"
	}
	
	# -------------------------------------------------------------------------------
	# VM renaming when not AD joined
	# -------------------------------------------------------------------------------
	[string[]] BuildRenameVMScript() {
		$Script = @()
		# renaming 
		$Script += 'hostnamectl set-hostname ' + $this.VMHostname

		return $Script
	}

	# -------------------------------------------------------------------------------
	# AD join
	#
	# https://computingforgeeks.com/join-ubuntu-debian-to-active-directory-ad-domain/
	# -------------------------------------------------------------------------------
	[string[]] BuildJoinADScript() {
		$Script = @()
		# AD packages installation
		$Script += 'apt-get -y install network-manager realmd sssd sssd-tools libnss-sss ' `
				   + 'libpam-sss adcli samba-common-bin oddjob oddjob-mkhomedir packagekit'
		# renaming (with full name)
		$Script += 'hostnamectl set-hostname ' + $this.VMHostname + '.' + $this.Config.'Domain.Name'
		# bug https://forum.proxmox.com/threads/sssd-realm-join.131067/
		$Script	+= 'echo ' + $this.Config.'Domain.Name'.ToUpper() + '| apt-get -y install krb5-user'			
		$Script += "sed -i '3irdns=false' /etc/krb5.conf"
		# AD joining (realname must be UPPERCASE)
		$Script += 'realm -v discover ' + $this.Config.'Domain.Name'
		$Script += 'echo ' + $this.Config.'Domain.Password' + ' | realm join --user=' `
					+ $this.Config.'Domain.Admin' + ' ' + $this.Config.'Domain.Name'.ToUpper()
		# home dir creation
		$Script += 'pam-auth-update --enable mkhomedir'
		# enables all AD users login 
		$Script += 'realm permit --all'
		# AD group admin-linux is sudoer
		$Script += "echo '%admin-linux@" + $this.Config.'Domain.Name' + "\tALL=(ALL) ALL' > /etc/sudoers.d/domain_admins"
		# checking
		$Script += 'id ' + $this.Config.'Domain.Admin' + '@' + $this.Config.'Domain.Name'
		$Script += 'realm list'	
	
		return $Script
	}

	# -------------------------------------------------------------------------------
	# Ad leaving
	# -------------------------------------------------------------------------------
	[string[]] BuildLeaveADScript() {
		$Script = @()
		# leaves domain (AD realname must be UPPERCASE)
		$Script += 'echo ' + $this.Config.'Domain.Password' + ' | realm leave ' `
					+ $this.Config.'Domain.Name'.ToUpper() + ' -U ' + $this.Config.'Domain.Admin' + ' --remove' 	

		return $Script
	}

	# -------------------------------------------------------------------------------
	# creates linux shell script (with eol handling)
	# -------------------------------------------------------------------------------
	[void] CreateScriptFile([string]$Path, [string[]]$Script) {
		$Val = ""
		foreach ($Line in $Script) {
			$Val += $Line
			$Val += ([Environment]::NewLine)
		}
		# linux format
		$Val = $Val -replace "`r`n","`n"
		Set-content $Path -NoNewLine -Value $Val
	}
	
	# -------------------------------------------------------------------------------
	# copies and runs a script on VM
	#
	# /etc/sudoers must contain
	#            <user> ALL=(root) NOPASSWD: /tmp/init.sh
	# -------------------------------------------------------------------------------
	[string] ExecScriptVM([string]$HostName,[string[]]$Script) {
		# script is created locally
		$InitScriptPath = [System.IO.Path]::GetTempPath() + 'init.sh'
		try {
			$this.CreateScriptFile($InitScriptPath, $Script)
			# script -> VM
			$this.CopyOnVM($HostName, $InitScriptPath, '/tmp/init.sh')
		} finally {
			# script is deleted
			Remove-Item -LiteralPath $InitScriptPath -Force
		}
		# execution and cleaning on VM
		plink $HostName -batch -l $this.Config.'Template.Login' -pw $this.Config.'Template.Password' 'chmod +x /tmp/init.sh'
		$Res = plink $HostName -batch -l $this.Config.'Template.Login' -pw $this.Config.'Template.Password' 'sudo /tmp/init.sh'	
		plink $HostName -batch -l $this.Config.'Template.Login' -pw $this.Config.'Template.Password' 'rm /tmp/init.sh'
		return $Res
	}

}

# -------------------------------------------------------------------------------
# WINDOWS 
# -------------------------------------------------------------------------------
class WindowsVMBuilder: VMBuilder {
	
	[string] GetFirstPuttyCommand() {
		return 'echo 1'
	}

	[string] GetVMDataDir() {
		return $this.Config.'VM.BaseDir'
	}

	[string] GetVMUpdateScript() {
		return "update.ps1"
	}
	
	[string] GetVMInfoScript() {
		return "get-infos.ps1"
	}

	# -------------------------------------------------------------------------------
	# renames a VM
	# -------------------------------------------------------------------------------
	[string] PreJoinAD([string] $IPv4) {
		$this.Log("Renommage avant jonction AD")
		$Script = $this.BuildRenameVMScript()
		$this.ExecScriptVM($IPv4,$Script)
		return ($this.RebootVM())
	}
	
	# -------------------------------------------------------------------------------
	# renames VM if not in domain
	# -------------------------------------------------------------------------------
	[string[]] BuildRenameVMScript() {
		$Script = @()
		# renaming 
		$Script += 'Rename-Computer -NewName ' + '"' + $this.VMHostname + '" -Force'
		return $Script
	}

	# -------------------------------------------------------------------------------
	# joins VM to domain
	# -------------------------------------------------------------------------------
	[string[]] BuildJoinADScript() {
		$Script = @()
		$Script += '$User = "' + $this.Config.'Domain.Admin' + '"'
		$Script += '$PWord = ConvertTo-SecureString -String "' + $this.Config.'Domain.Password' + '" -AsPlainText -Force'
		$Script += '$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord'
		$Script += 'Add-Computer -Credential $Cred -DomainName "' + $this.Config.'Domain.name' + '" -Force'
		return $Script
	}

	# -------------------------------------------------------------------------------
	# VM leaves domain (cleaning)
	# -------------------------------------------------------------------------------
	[string[]] BuildLeaveADScript() {
		$Script = @()	
		$Script += '$User = "' + $this.Config.'Domain.Admin' + '"'
		$Script += '$PWord = ConvertTo-SecureString -String "' + $this.Config.'Domain.Password' + '" -AsPlainText -Force'
		$Script += '$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord'
		$Script += 'Remove-Computer -WorkgroupName "TEMP" -UnjoinDomainCredential $Cred -Force'
		return $Script
	}
	
	# -------------------------------------------------------------------------------
	# copies and runs powershell script on VM (with gsudo)
	#
	# https://winget.run/pkg/gerardog/gsudo
	#
	# -------------------------------------------------------------------------------
	[string] ExecScriptVM([string]$HostName,[string[]]$Script) {
		# script created locally
		$ScriptName = 'init.ps1'
		$RemotePath = 'C:/Temp/' + $ScriptName
		$InitScriptPath = [System.IO.Path]::GetTempPath() + $ScriptName
		try {
			$this.CreateScriptFile($InitScriptPath, $Script)
			# script -> VM
			$this.CopyOnVM($HostName, $InitScriptPath, $RemotePath)
		} finally {
			# destroys local script
			Remove-Item -LiteralPath $InitScriptPath -Force
		}
		# execution and cleaning
		$ExecCommand = 'powershell gsudo C:\Temp\' + $ScriptName
		$Res = plink $HostName -batch -l $this.Config.'Template.Login' -pw $this.Config.'Template.Password' $ExecCommand 
		$DelCommand = 'Remove-Item -LiteralPath ' + $RemotePath + ' -Force'
		$ExecCommand = 'powershell gsudo powershell -noprofile -executionpolicy Unrestricted -command {' + $DelCommand + '}'
		plink $HostName -batch -l $this.Config.'Template.Login' -pw $this.Config.'Template.Password' $ExecCommand
		$Res >> $this.LogFile
		return $Res
	}

}

