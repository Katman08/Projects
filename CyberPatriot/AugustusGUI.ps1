$user = $env:UserName

if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
     $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
     Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
     Exit
    }
}

if (!(Test-Path C:\Users\$user\Desktop\AugustusOut)) {
New-Item -Path C:\Users\$user\Desktop\AugustusOut -ItemType Directory
}
if (!(Test-Path C:\Users\$user\Desktop\AugustusOut\userfiles)) {
New-Item -Path C:\Users\$user\Desktop\AugustusOut\userfiles -ItemType directory
}
if (!(Test-Path C:\Users\$user\Desktop\AugustusOut\programfiles)) {
New-Item -Path C:\Users\$user\Desktop\AugustusOut\programfiles -ItemType directory
}
if (!(Test-Path C:\Users\$user\Desktop\AugustusOut\programfilesx86)) {
New-Item -Path C:\Users\$user\Desktop\AugustusOut\programfilesx86 -ItemType directory
}
if (!(Test-Path C:\Users\$user\Desktop\AugustusOut\documents)) {
New-Item -Path C:\Users\$user\Desktop\AugustusOut\documents -ItemType directory
}
if (!(Test-Path C:\Users\$user\Desktop\AugustusOut\OS_search_engine)) {
New-Item -Path C:\Users\$user\Desktop\AugustusOut\OS_search_engine -ItemType directory
}
if (!(Test-Path C:\Users\$user\Desktop\AugustusOut\new_programs)) {
New-Item -Path C:\Users\$user\Desktop\AugustusOut\new_programs -ItemType directory
}
if (!(Test-Path C:\Users\$user\Desktop\AugustusOut\Suspicious_Shit.txt)) {
New-Item -Path C:\Users\$user\Desktop\AugustusOut\Suspicious_Shit.txt -ItemType file
}

###Menu Options

function fileDump {
	$TextBox1.appendtext("----------------File-Dump----------------")
	$TextBox1.appendtext("
")
	try 
	{
		Get-ChildItem -Path "C:\Users\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\AugustusOut\userfiles -ErrorAction stop
		$TextBox1.appendtext("Media files have been added to userfiles.txt")
		$TextBox1.appendtext("
")
	}
	catch 
	{
		$TextBox1.appendtext("Files have already been recorded")
		$TextBox1.appendtext("
")
	}
		

}

function RenameDfts {
    
	$TextBox1.appendtext("----------------Rename-Defaults----------------")
	$TextBox1.appendtext("
")

    try {
    Get-LocalUser Guest -ErrorAction stop | Disable-LocalUser
    Get-LocalUser Administrator -ErrorAction stop | Disable-LocalUser
	$TextBox1.appendtext("Default accounts were renamed")
	$TextBox1.appendtext("
")

    Rename-LocalUser -Name "Administrator" -NewName "CPAdministrator" -ErrorAction stop
    Rename-LocalUser -Name "Guest" -NewName "CPGuest" -ErrorAction stop
    }
    Catch {$TextBox1.appendtext("Default accounts were not renamed")
	$TextBox1.appendtext("
")
	}

}

function passPol {
    $TextBox1.appendtext("----------------Password-Policy----------------")
    $TextBox1.appendtext("
")
    $TextBox1.appendtext("Setting Secure Password Policies")
    $TextBox1.appendtext("
")
    net accounts /UNIQUEPW:5 /MAXPWAGE:30 /MINPWAGE:5 /MINPWLEN:10 /lockoutthreshold:5
    $TextBox1.appendtext("Starting Security Policy Manager")
    $TextBox1.appendtext("
")
    $TextBox1.appendtext("Manually secure the following settings")
	$TextBox1.appendtext("
")
    $TextBox1.appendtext("Password must meet complexity requirements")
	$TextBox1.appendtext("
")
    $TextBox1.appendtext("Store passwords using reversible encryption")
    $TextBox1.appendtext("
")
    Start-Process -FilePath secpol.msc

}

function auditPol {
    $TextBox1.appendtext("----------------Audit-Policies----------------")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Setting all Audit Policies to Success/Failure")
    $TextBox1.appendtext("
")

    Start-Process -FilePath secpol.msc
	Start-Process -FilePath powershell.exe -verb runas
	
    $TextBox1.appendtext("Make sure it worked becuase sometimes its a little bitch")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("If it didnt run the commands in the other textbox")
	$TextBox1.appendtext("
")
	$TextBox2.visible = $true
	$TextBox2.appendtext("
auditpol /set /category:'Account Logon' /success:enable /failure:enable
auditpol /set /category:'Account Management' /success:enable /failure:enable
auditpol /set /category:'DS Access' /success:enable /failure:enable
auditpol /set /category:'Logon/Logoff' /success:enable /failure:enable
auditpol /set /category:'Object Access' /success:enable /failure:enable
auditpol /set /category:'Policy Change' /success:enable /failure:enable
auditpol /set /category:'Privilege Use' /success:enable /failure:enable
auditpol /set /category:'Detailed Tracking' /success:enable /failure:enable
auditpol /set /category:'System' /success:enable /failure:enable
	")
}

function netShare {
    $TextBox1.appendtext("----------------Net-Shares----------------")
 	$TextBox1.appendtext("
")
	$TextBox2.visible = $true
	$TextBox2.appendtext("
")
	$TextBox2.appendtext("--------------------------------Net-Shares--------------------------------")
	$TextBox2.appendtext("
")
    if (!(Test-Path C:\Users\$user\Desktop\AugustusOut\shares.txt)) {New-Item -Path C:\Users\$user\Desktop\AugustusOut\shares.txt}
   	net share | Set-Content C:\Users\$user\Desktop\AugustusOut\shares.txt
	$TextBox2.visible = $true
	$v2 = net share
	$TextBox2.appendtext($v2)
	$TextBox2.appendtext("
")
	$TextBox1.appendtext("Net Shares added to shares.txt")
	$TextBox1.appendtext("
")

    
}

function hosts {
    $TextBox1.appendtext("----------------Host-File----------------")
	$TextBox1.appendtext("
")
	$TextBox2.visible = $true
	$TextBox2.appendtext("--------------------------------Host-File--------------------------------")
	$TextBox2.appendtext("  
")
 
	$hstring = Get-content -Path "C:\Windows\System32\drivers\etc\hosts"

	if ($null -eq $hstring)
	 {
		$TextBox2.appendtext("Host file has already been cleared")
		$TextBox2.appendtext("
")
		} else {
			foreach ($line in $hstring) {
				$TextBox2.appendtext($line)
				$TextBox2.appendtext("
")
			}
	}
	
	if (!(Test-Path C:\Users\$user\Desktop\AugustusOut\hosts.txt)) {
        New-Item -Path C:\Users\$user\Desktop\AugustusOut\hosts.txt
    }

    Get-ChildItem -Path "C:\Windows\System32\drivers\etc\hosts" | Copy-Item -Destination C:\Users\$user\Desktop\AugustusOut\hosts.txt
    Clear-Content "C:\Windows\System32\drivers\etc\hosts"
	$TextBox1.appendtext("Host file backed up in hosts.txt")
	$TextBox1.appendtext("
")
    
}

function weakServices {
    $TextBox1.appendtext("----------------Weak-Services-----------------")
	$TextBox1.appendtext("
")

    dism /online /disable-feature /featurename:IIS-WebServerRole
	dism /online /disable-feature /featurename:IIS-WebServer
	dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
	dism /online /disable-feature /featurename:IIS-HttpErrors
	dism /online /disable-feature /featurename:IIS-HttpRedirect
	dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
	dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
	dism /online /disable-feature /featurename:IIS-HttpLogging
	dism /online /disable-feature /featurename:IIS-LoggingLibraries
	dism /online /disable-feature /featurename:IIS-RequestMonitor
	dism /online /disable-feature /featurename:IIS-HttpTracing
	dism /online /disable-feature /featurename:IIS-Security
	dism /online /disable-feature /featurename:IIS-URLAuthorization
	dism /online /disable-feature /featurename:IIS-RequestFiltering
	dism /online /disable-feature /featurename:IIS-IPSecurity
	dism /online /disable-feature /featurename:IIS-Performance
	dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
	dism /online /disable-feature /featurename:IIS-WebServerManagementTools
	dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
	dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
	dism /online /disable-feature /featurename:IIS-Metabase
	dism /online /disable-feature /featurename:IIS-HostableWebCore
	dism /online /disable-feature /featurename:IIS-StaticContent
	dism /online /disable-feature /featurename:IIS-DefaultDocument
	dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
	dism /online /disable-feature /featurename:IIS-WebDAV
	dism /online /disable-feature /featurename:IIS-WebSockets
	dism /online /disable-feature /featurename:IIS-ApplicationInit
	dism /online /disable-feature /featurename:IIS-ASPNET
	dism /online /disable-feature /featurename:IIS-ASPNET45
	dism /online /disable-feature /featurename:IIS-ASP
	dism /online /disable-feature /featurename:IIS-CGI 
	dism /online /disable-feature /featurename:IIS-ISAPIExtensions
	dism /online /disable-feature /featurename:IIS-ISAPIFilter
	dism /online /disable-feature /featurename:IIS-ServerSideIncludes
	dism /online /disable-feature /featurename:IIS-CustomLogging
	dism /online /disable-feature /featurename:IIS-BasicAuthentication
	dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
	dism /online /disable-feature /featurename:IIS-ManagementConsole
	dism /online /disable-feature /featurename:IIS-ManagementService
	dism /online /disable-feature /featurename:IIS-WMICompatibility
	dism /online /disable-feature /featurename:IIS-LegacyScripts
	dism /online /disable-feature /featurename:IIS-LegacySnapIn
	dism /online /disable-feature /featurename:IIS-FTPServer
	dism /online /disable-feature /featurename:IIS-FTPSvc
	dism /online /disable-feature /featurename:IIS-FTPExtensibility
	dism /online /disable-feature /featurename:TFTP
	dism /online /disable-feature /featurename:TelnetClient
	dism /online /disable-feature /featurename:TelnetServer
    dism /online /disable-feature /featurename:"SMB1Protocol"
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

    $TextBox1.appendtext("Did a secure")
	$TextBox1.appendtext("
")
}

function processes {
    $TextBox1.appendtext("----------------Suspicious-Processes----------------")
	$TextBox1.appendtext("
")
    Get-Process | Where-Object {$_.WorkingSet -gt 20000000} > C:\Users\$user\Desktop\AugustusOut\Suspicious_Shit.txt
	$TextBox1.appendtext("A list of Suspicious Processes has been added to suspiciousProcesses.txt")
	$TextBox1.appendtext("
")
    
}

function firewall {
    $TextBox1.appendtext("----------------Firewall-Settings----------------")
    $TextBox1.appendtext("
")
    $TextBox1.appendtext("Enabling Windows Firewall")
    $TextBox1.appendtext("
")
    $TextBox1.appendtext("Configuring Windows Firewall")
    $TextBox1.appendtext("
")
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

    
}

function ports {
    $TextBox1.appendtext("----------------Blocking-Ports----------------")
    $TextBox1.appendtext("
")
    $TextBox1.appendtext("Chalaan made this part idk what it does")
    $TextBox1.appendtext("
")
    netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
    netsh advfirewall firewall set rule name="netcat" new enable=no
    #disable network discovery hopefully
    netsh advfirewall firewall set rule group="Network Discovery" new enable=No
    #disable file and printer sharing hopefully
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No

    netsh advfirewall firewall add rule name="block_RemoteRegistry_in" dir=in service="RemoteRegistry" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RemoteRegistry_out" dir=out service="RemoteRegistry" action=block enable=yes

    $Cports =@("20", "21", "23", "25","110", "135", "411", "412", "445", "161", "162", "636", "3269", "3389")

    foreach ($port in $Cports) {

        $RName0 = "Block Outbound Port" + $port
        $RName1 = "Block Inbound Port" + $port

        New-NetFirewallRule -DisplayName $RName0 -Direction Outbound -LocalPort $port -Protocol TCP -Action Block
        New-NetFirewallRule -DisplayName $RName1 -Direction Inbound -LocalPort $port -Protocol TCP -Action Block
        $TextBox1.appendtext("Blocked port $port")
		$TextBox1.appendtext("
		")
    }

    #network profile to public so it denies file sharing, device discovery, etc.
    Set-NetConnectionProfile -NetworkCategory Public
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue

    
}

function remoteDesktop {
    $TextBox1.appendtext("----------------Disable-Remote Desktop----------------")
	$TextBox1.appendtext("
")

    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing" /v "NoRDS" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d 80 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d 0 /f
    $TextBox1.appendtext("Remote Desktop is disabled")
	$TextBox1.appendtext("
")
    
}

function autoUpdate {
    $TextBox1.appendtext("----------------Enable-Auto-Update----------------")
	$TextBox1.appendtext("
")
    $TextBox1.appendtext("also disabling the msg command bc that is evil")
	$TextBox1.appendtext("
")

    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f

    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "AllowRemoteRPC" /t "REG_DWORD" /d "0" /f

    $TextBox1.appendtext("if your seeing this then it didnt crash *yay*")
	$TextBox1.appendtext("
")

}

function secOpt {
    $TextBox1.appendtext("----------------Making-this-Boi-Secure----------------")
	$TextBox1.appendtext("
")

    #Restrict CD ROM drive
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

    #disable remote access to floppy disk
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f

    #disable auto admin login
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

    #clear page file
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f

    #no printer drivers
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

    #auditing to LSASS.exe
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f

    #Enable LSA protection
    reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f

    #Limit use of blank passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
    
    #Auditing access of Global System Objects
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
    
    #Auditing Backup and Restore
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f
    
    #Restrict Anonymous Enumeration #1
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
    
    #Restrict Anonymous Enumeration #2
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
    
    #Disable storage of domain passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
    
    #Take away Anonymous user Everyone permissions
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
    
    #Allow Machine ID for NTLM
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
    
    #Do not display last user on logon
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
    
    #Enable UAC
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

    #UAC set high
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
    
    #UAC setting (Prompt on Secure Desktop)
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    
    #Enable Installer Detection
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
    
    #Disable undocking without logon
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
    
    #Enable CTRL+ALT+DEL
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
    
    #Max password age
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f

    #Disable machine account password changes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
    
    #Require strong session key
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
    
    #Require Sign/Seal
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
    
    #Sign Channel
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
    
    #Seal Channel
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
    
    #Set idle time to 45 minutes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
    
    #Require Security Signature - Disabled pursuant to checklist:::
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f
    
    #Enable Security Signature - Disabled pursuant to checklist:::
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f
    
    #Clear null session pipes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
    
    #Restict Anonymous user access to named pipes and shares
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
    
    #Encrypt SMB Passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
    
    #Clear remote registry paths
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
    
    #Clear remote registry paths and sub-paths
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
    
    #Enable smart screen for IE8
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
    $TextBox1.appendtext("doing cool stuff")
	$TextBox1.appendtext("
")
    #Enable smart screen for IE9 and up
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
    
    #Disable IE password caching
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
    
    #Warn users if website has a bad certificate
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
    
    #Warn users if website redirects
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
    
    #Enable Do Not Track
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f

    #Show hidden files
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
    
    #Disable sticky keys
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
    
    #Show super hidden files
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
    
    #Disable dump file creation
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
    
    #Disable autoruns
    reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

    #enable internet explorer phishing filter
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
    $TextBox1.appendtext("still doing cool stuff")
	$TextBox1.appendtext("
")
    #block macros and other content execution
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f
    $TextBox1.appendtext("doing cooler stuff")
	$TextBox1.appendtext("
")
    #Enable Windows Defender
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f

    
}

function services {
    $TextBox1.appendtext("----------------We-are-doing-the-macerena----------------")
    $TextBox1.appendtext("
")

	cmd.exe /c 'sc stop tlntsvr'
	cmd.exe /c 'sc config tlntsvr start= disabled'
	cmd.exe /c 'sc stop msftpsvc'
	cmd.exe /c 'sc config msftpsvc start= disabled'
	cmd.exe /c 'sc stop snmptrap'
	cmd.exe /c 'sc config snmptrap start= disabled'
	cmd.exe /c 'sc stop ssdpsrv'
	cmd.exe /c 'sc config ssdpsrv start= disabled'
	cmd.exe /c 'sc stop termservice'
	cmd.exe /c 'sc config termservice start= disabled'
	cmd.exe /c 'sc stop sessionenv'
	cmd.exe /c 'sc config sessionenv start= disabled'
	cmd.exe /c 'sc stop remoteregistry'
	cmd.exe /c 'sc config remoteregistry start= disabled'
	cmd.exe /c 'sc stop Messenger'
	cmd.exe /c 'sc config Messenger start= disabled'
	cmd.exe /c 'sc stop upnphos'
	cmd.exe /c 'sc config upnphos start= disabled'
	cmd.exe /c 'sc stop WAS'
	cmd.exe /c 'sc config WAS start= disabled'
	cmd.exe /c 'sc stop RemoteAccess'
	cmd.exe /c 'sc config RemoteAccess start= disabled'
	cmd.exe /c 'sc stop mnmsrvc'
	cmd.exe /c 'sc config mnmsrvc start= disabled'
	cmd.exe /c 'sc stop NetTcpPortSharing'
	cmd.exe /c 'sc config NetTcpPortSharing start= disabled'
	cmd.exe /c 'sc stop RasMan'
	cmd.exe /c 'sc config RasMan start= disabled'
	cmd.exe /c 'sc stop TabletInputService'
	cmd.exe /c 'sc config TabletInputService start= disabled'
	cmd.exe /c 'sc stop RpcSs'
	cmd.exe /c 'sc config RpcSs start= disabled'
	cmd.exe /c 'sc stop SENS'
	cmd.exe /c 'sc config SENS start= disabled'
	cmd.exe /c 'sc stop EventSystem'
	cmd.exe /c 'sc config EventSystem start= disabled'
	cmd.exe /c 'sc stop XblAuthManager'
	cmd.exe /c 'sc config XblAuthManager start= disabled'
	cmd.exe /c 'sc stop XblGameSave'
	cmd.exe /c 'sc config XblGameSave start= disabled'
	cmd.exe /c 'sc stop XboxGipSvc'
	cmd.exe /c 'sc config XboxGipSvc start= disabled'
	cmd.exe /c 'sc stop xboxgip'
	cmd.exe /c 'sc config xboxgip start= disabled'
	cmd.exe /c 'sc stop xbgm'
	cmd.exe /c 'sc config xbgm start= disabled'
	cmd.exe /c 'sc stop SysMain'
	cmd.exe /c 'sc config SysMain start= disabled'
	cmd.exe /c 'sc stop seclogon'
	cmd.exe /c 'sc config seclogon start= disabled'
	cmd.exe /c 'sc stop TapiSrv'
	cmd.exe /c 'sc config TapiSrv start= disabled'
	cmd.exe /c 'sc stop p2pimsvc'
	cmd.exe /c 'sc config p2pimsvc start= disabled'
	cmd.exe /c 'sc stop simptcp'
	cmd.exe /c 'sc config simptcp start= disabled'
	cmd.exe /c 'sc stop fax'
	cmd.exe /c 'sc config fax start= disabled'
	cmd.exe /c 'sc stop Msftpsvc'
	cmd.exe /c 'sc config Msftpsvc start= disabled'
	cmd.exe /c 'sc stop iprip'
	cmd.exe /c 'sc config iprip start= disabled'
	cmd.exe /c 'sc stop ftpsvc'
	cmd.exe /c 'sc config ftpsvc start= disabled'
	cmd.exe /c 'sc stop RasAuto'
	cmd.exe /c 'sc config RasAuto start= disabled'
	cmd.exe /c 'sc stop W3svc'
	cmd.exe /c 'sc config W3svc start= disabled'
	cmd.exe /c 'sc stop Smtpsvc'
	cmd.exe /c 'sc config Smtpsvc start= disabled'
	cmd.exe /c 'sc stop Dfs'
	cmd.exe /c 'sc config Dfs start= disabled'
	cmd.exe /c 'sc stop TrkWks'
	cmd.exe /c 'sc config TrkWks start= disabled'
	cmd.exe /c 'sc stop MSDTC'
	cmd.exe /c 'sc config MSDTC start= disabled'
	cmd.exe /c 'sc stop ERSvc'
	cmd.exe /c 'sc config ERSvc start= disabled'
	cmd.exe /c 'sc stop NtFrs'
	cmd.exe /c 'sc config NtFrs start= disabled'
	cmd.exe /c 'sc stop Iisadmin'
	cmd.exe /c 'sc config Iisadmin start= disabled'
	cmd.exe /c 'sc stop IsmServ'
	cmd.exe /c 'sc config IsmServ start= disabled'
	cmd.exe /c 'sc stop WmdmPmSN'
	cmd.exe /c 'sc config WmdmPmSN start= disabled'
	cmd.exe /c 'sc stop helpsvc'
	cmd.exe /c 'sc config helpsvc start= disabled'
	cmd.exe /c 'sc stop Spooler'
	cmd.exe /c 'sc config Spooler start= disabled'
	cmd.exe /c 'sc stop RDSessMgr'
	cmd.exe /c 'sc config RDSessMgr start= disabled'
	cmd.exe /c 'sc stop RSoPProv'
	cmd.exe /c 'sc config RSoPProv start= disabled'
	cmd.exe /c 'sc stop SCardSvr'
	cmd.exe /c 'sc config SCardSvr start= disabled'
	cmd.exe /c 'sc stop lanmanserver'
	cmd.exe /c 'sc config lanmanserver start= disabled'
	cmd.exe /c 'sc stop Sacsvr'
	cmd.exe /c 'sc config Sacsvr start= disabled'
	cmd.exe /c 'sc stop TermService'
	cmd.exe /c 'sc config TermService start= disabled'
	cmd.exe /c 'sc stop uploadmgr'
	cmd.exe /c 'sc config uploadmgr start= disabled'
	cmd.exe /c 'sc stop VDS'
	cmd.exe /c 'sc config VDS start= disabled'
	cmd.exe /c 'sc stop VSS'
	cmd.exe /c 'sc config VSS start= disabled'
	cmd.exe /c 'sc stop WINS'
	cmd.exe /c 'sc config WINS start= disabled'
	cmd.exe /c 'sc stop CscService'
	cmd.exe /c 'sc config CscService start= disabled'
	cmd.exe /c 'sc stop hidserv'
	cmd.exe /c 'sc config hidserv start= disabled'
	cmd.exe /c 'sc stop IPBusEnum'
	cmd.exe /c 'sc config IPBusEnum start= disabled'
	cmd.exe /c 'sc stop PolicyAgent'
	cmd.exe /c 'sc config PolicyAgent start= disabled'
	#cmd.exe /c 'sc stop SCPolicySvc'
	#cmd.exe /c 'sc config SCPolicySvc start= disabled'
	cmd.exe /c 'sc stop SharedAccess'
	cmd.exe /c 'sc config SharedAccess start= disabled'
	cmd.exe /c 'sc stop SSDPSRV'
	cmd.exe /c 'sc config SSDPSRV start= disabled'
	cmd.exe /c 'sc stop Themes'
	cmd.exe /c 'sc config Themes start= disabled'
	cmd.exe /c 'sc stop upnphost'
	cmd.exe /c 'sc config upnphost start= disabled'
	cmd.exe /c 'sc stop nfssvc'
	cmd.exe /c 'sc config nfssvc start= disabled'
	cmd.exe /c 'sc stop nfsclnt'
	cmd.exe /c 'sc config nfsclnt start= disabled'
	cmd.exe /c 'sc stop MSSQLServerADHelper'
	cmd.exe /c 'sc config MSSQLServerADHelper start= disabled'
	cmd.exe /c 'sc stop SharedAccess'
	cmd.exe /c 'sc config SharedAccess start= disabled'
	cmd.exe /c 'sc stop UmRdpService'
	cmd.exe /c 'sc config UmRdpService start= disabled'
	cmd.exe /c 'sc stop SessionEnv'
	cmd.exe /c 'sc config SessionEnv start= disabled'
	cmd.exe /c 'sc stop Server'
	cmd.exe /c 'sc config Server start= disabled'
	cmd.exe /c 'sc stop TeamViewer'
	cmd.exe /c 'sc config TeamViewer start= disabled'
	cmd.exe /c 'sc stop TeamViewer7'
	cmd.exe /c 'sc config start= disabled'
	cmd.exe /c 'sc stop HomeGroupListener'
	cmd.exe /c 'sc config HomeGroupListener start= disabled'
	cmd.exe /c 'sc stop HomeGroupProvider'
	cmd.exe /c 'sc config HomeGroupProvider start= disabled'
	cmd.exe /c 'sc stop AxInstSV'
	cmd.exe /c 'sc config AXInstSV start= disabled'
	cmd.exe /c 'sc stop Netlogon'
	cmd.exe /c 'sc config Netlogon start= disabled'
	cmd.exe /c 'sc stop lltdsvc'
	cmd.exe /c 'sc config lltdsvc start= disabled'
	cmd.exe /c 'sc stop iphlpsvc'
	cmd.exe /c 'sc config iphlpsvc start= disabled'
	cmd.exe /c 'sc stop AdobeARMservice'
	cmd.exe /c 'sc config AdobeARMservice start= disabled'
    $TextBox1.appendtext("doing cool stuff")
	$TextBox1.appendtext("
")
	#goodservices
	cmd.exe /c 'sc start wuauserv'
	cmd.exe /c 'sc config wuauserv start= auto'
	cmd.exe /c 'sc start EventLog'
	cmd.exe /c 'sc config EventLog start= auto'
	cmd.exe /c 'sc start MpsSvc'
	cmd.exe /c 'sc config MpsSvc start= auto'
	cmd.exe /c 'sc start WinDefend'
	cmd.exe /c 'sc config WinDefend start= auto'
	cmd.exe /c 'sc start WdNisSvc'
	cmd.exe /c 'sc config WdNisSvc start= auto'
	cmd.exe /c 'sc start Sense'
	cmd.exe /c 'sc config Sense start= auto'
	cmd.exe /c 'sc start Schedule'
	cmd.exe /c 'sc config Schedule start= auto'
	cmd.exe /c 'sc start SCardSvr'
	cmd.exe /c 'sc config SCardSvr start= auto'
	cmd.exe /c 'sc start ScDeviceEnum'
	cmd.exe /c 'sc config ScDeviceEnum start= auto'
	cmd.exe /c 'sc start SCPolicySvc'
	cmd.exe /c 'sc config SCPolicySvc start= auto'
	cmd.exe /c 'sc start wscsvc'
	cmd.exe /c 'sc config wscsvc start= auto'

    
}

function scheduledTasks {
	$TextBox1.appendtext("----------------Scheduled-Tasks----------------")
	$TextBox1.appendtext("
")
    $TextBox1.appendtext("Gettimg a list of all scheduled tasks")
  	$TextBox1.appendtext("
")
    $v3 = @()
	$schtasks = schtasks /query /fo table | findstr /c:"Folder: "
    foreach ($line in $schtasks) {
        $line -replace "Folder: "
		$v3 += $line
        }
    
    if (!(Test-Path C:\Users\$user\Desktop\AugustusOut\SchTasks.txt)) {
    	New-Item -Path C:\Users\$user\Desktop\AugustusOut\SchTasks.txt
		schtasks /query /fo table | findstr /c:"Folder" | Add-Content C:\Users\$user\Desktop\AugustusOut\SchTasks.txt
        $TextBox1.appendtext("A list of all scheduled tasks has been added to SchTasks.txt")
   		$TextBox1.appendtext("
")
    }
    else {
    
    	$TextBox1.appendtext("A list of all scheduled tasks has already been added to SchTasks.txt")
		$TextBox1.appendtext("
")
    }
	$TextBox2.visible = $true
	$TextBox2.appendtext("--------------------------------Scheduled-Tasks--------------------------------")
	$TextBox2.appendtext("
")
	$TextBox2.appendtext($v3)
	$TextBox2.appendtext("
")
	$TextBox1.appendtext("Starting Task Scheduler")
	$TextBox1.appendtext("
")
	Start-Process -FilePath taskschd.msc
    
}

function programs {
	$TextBox1.appendtext("----------------Useful-Programs----------------")
	$TextBox1.appendtext("
")
    ###Download CCleaner
    if (Test-Path "C:\Users\$user\Desktop\AugustusOut\new_programs\ccsetup563.exe"){
        $TextBox1.appendtext("CCleaner already downloaded")
		$TextBox1.appendtext("
")
    } else {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Katman08/ccleaner/master/ccsetup563.exe" -OutFile "C:\Users\$user\Desktop\AugustusOut\new_programs\ccsetup563.exe" 
        $TextBox1.appendtext("CCleaner has been downloaded")
		$TextBox1.appendtext("
")
    }
    
    ###Download MalwareBytes
    if (Test-Path "C:\Users\$user\Desktop\AugustusOut\new_programs\MBSetup.exe"){
        $TextBox1.appendtext("MalwareBytes already installed")
		$TextBox1.appendtext("
")
    } else {
        Invoke-WebRequest -Uri "https://data-cdn.mbamupdates.com/web/mb4-setup-consumer/MBSetup.exe" -OutFile "C:\Users\$user\Desktop\AugustusOut\new_programs\MBSetup.exe"
        $TextBox1.appendtext("Malwarebytes has been downloaded")
		$TextBox1.appendtext("
")
    }
	###Download Process Explorer
    if (Test-Path "C:\Users\$user\Desktop\AugustusOut\new_programs\PExplorer"){
        $TextBox1.appendtext("Process Explorer already installed")
		$TextBox1.appendtext("
")
    } else { 
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/ProcessExplorer.zip" -OutFile "C:\Users\$user\Desktop\AugustusOut\new_programs\ProcessExplorer.zip"
        New-Item -Path C:\Users\$user\Desktop\AugustusOut\PExplorer -ItemType Directory
        Expand-Archive -LiteralPath C:\Users\$user\Desktop\AugustusOut\new_programs\ProcessExplorer.zip -DestinationPath C:\Users\$user\Desktop\AugustusOut\new_programs\PExplorer -Force
	    Remove-Item C:\Users\$user\Desktop\AugustusOut\new_programs\ProcessExplorer.zip -Recurse -Force -Confirm:$false
        $TextBox1.appendtext("Process Explorer has been downloaded")
	    $TextBox1.appendtext("
")

    ###Download extra script

    if (Test-Path "C:\Users\$user\Desktop\AugustusOut\new_programs\scripts"){
        $TextBox1.appendtext("Extra scripts already downloaded")
		$TextBox1.appendtext("
")
    } else { 
        try {Invoke-WebRequest -Uri "https://codeload.github.com/C0ntra99/CyberPatriot/zip/master" -OutFile "C:\Users\$user\Desktop\AugustusOut\new_programs\CyberPatriot-master.zip"
        New-Item -Path C:\Users\$user\Desktop\AugustusOut\Scripts -ItemType Directory
        Expand-Archive -LiteralPath C:\Users\$user\Desktop\AugustusOut\new_programs\CyberPatriot-master.zip -DestinationPath C:\Users\$user\Desktop\AugustusOut\new_programs\Scripts -Force
	    Remove-Item C:\Users\$user\Desktop\AugustusOut\new_programs\CyberPatriot-master.zip -Recurse -Force -Confirm:$false
        $TextBox1.appendtext("Extra scripts have been downloaded")
	    $TextBox1.appendtext("
")
    } catch {
        $TextBox1.appendtext("guess what it broke so use this link")
	    $TextBox1.appendtext("
")
        $TextBox1.appendtext("https://codeload.github.com/C0ntra99/CyberPatriot/zip/master")
	    $TextBox1.appendtext("
")
        }
    }

	$TextBox1.appendtext("Starting Various Installers")
	$TextBox1.appendtext("
")
    Start-Process -FilePath "C:\Users\$user\Desktop\AugustusOut\new_programs\ccsetup563.exe"
    Start-Process -FilePath "C:\Users\$user\Desktop\AugustusOut\new_programs\MBSetup.exe"
    Start-Process -FilePath  "C:\Users\$user\Desktop\AugustusOut\new_programs"
    
    

   }
}

function godmode {
	$TextBox1.appendtext("----------------Creating-God-mode----------------")
	$TextBox1.appendtext("
")

    try {
        if (!(Test-Path "C:\Users\$user\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}")) { 
            New-Item -Path "C:\Users\$user\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -ItemType directory -ErrorAction stop
            $TextBox1.appendtext("God mode has been added to your desktop")
			$TextBox1.appendtext("
")
            Start-Process -FilePath "C:\Users\$user\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -ErrorAction stop
        } else {
            $TextBox1.appendtext("God mode has already been created bro")
			$TextBox1.appendtext("
")
        }
    } 
    catch {
        $TextBox1.appendtext("God Mode cannot be created for some stupid reason")
		$TextBox1.appendtext("
")
    }


}

function SecureANDenableRDP {

	$TextBox1.appendtext("----------------Securing-RDP----------------")
	$TextBox1.appendtext("
")

    Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\‘ -Name “fDenyTSConnections” -Value 0
	Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\‘ -Name “UserAuthentication” -Value 1
	Enable-NetFirewallRule -DisplayGroup “Remote Desktop”

	$TextBox1.appendtext("Opening Sytem Properties")
	$TextBox1.appendtext("
")

start-process -filepath "SystemPropertiesRemote.exe"

}

function removeDefaultApps{

	$TextBox1.appendtext("----------------Remove-Default-Apps----------------")
	$TextBox1.appendtext("
")
 
    try {
        Get-AppxPackage 3dbuilder | Remove-AppxPackage
        Get-AppxPackage windowscalculator | Remove-AppxPackage
        Get-AppxPackage windowscommunicationsapps | Remove-AppxPackage
        Get-AppxPackage windowscamera | Remove-AppxPackage
        Get-AppxPackage officehub | Remove-AppxPackage
        Get-AppxPackage skypeapp | Remove-AppxPackage
        Get-AppxPackage getstarted | Remove-AppxPackage
        Get-AppxPackage zunemusic | Remove-AppxPackage
        Get-AppxPackage windowsmaps | Remove-AppxPackage
        Get-AppxPackage solitairecollection | Remove-AppxPackage
        Get-AppxPackage bingfinance | Remove-AppxPackage
        Get-AppxPackage zunevideo | Remove-AppxPackage
        Get-AppxPackage bingnews | Remove-AppxPackage
        Get-AppxPackage onenote | Remove-AppxPackage
        Get-AppxPackage people | Remove-AppxPackage
        Get-AppxPackage windowsphone | Remove-AppxPackage
        Get-AppxPackage photos | Remove-AppxPackage
        Get-AppxPackage windowsstore | Remove-AppxPackage
        Get-AppxPackage bingsports | Remove-AppxPackage
        Get-AppxPackage soundrecorder | Remove-AppxPackage
        Get-AppxPackage bingweather | Remove-AppxPackage
        Get-AppxPackage xboxapp | Remove-AppxPackage
        } 
        catch {
        	$TextBox1.appendtext("something broke")
	        $TextBox1.appendtext("
")
        }

	$TextBox1.appendtext("The following programs have been uninstalled:")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("3d Builder")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Calculator")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Camera App")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Office Hub")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Skype")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Get Started")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Zune")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Bing News")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("One Note")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("People")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Windows Phone")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Photos")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Windows Store")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Bing Sports")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Sound Recorder")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Bing Weather")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Xbox App")
	$TextBox1.appendtext("
")

}

function UserRights {

	$TextBox1.appendtext("----------------User-Rights----------------")
	$TextBox1.appendtext("
")
	$TextBox1.appendtext("Importing module")
	$TextBox1.appendtext("
")
    
    if (Test-Path "C:\Users\$user\Desktop\AugustusOut\UserRights.psm1"){
        $TextBox1.appendtext("Module already imported")
		$TextBox1.appendtext("
")
    } else { 
        Invoke-WebRequest -Uri "https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0/file/198800/1/UserRights.psm1" -OutFile "C:\Users\$user\Desktop\AugustusOut\UserRights.psm1"
        Import-Module C:\Users\$user\Desktop\AugustusOut\UserRights.psm1
        $TextBox1.appendtext("Module successfully imported")
		$TextBox1.appendtext("
")

}

foreach ($right in @("SeSystemtimePrivilege", "SeTimeZonePrivilege")) {
    Grant-UserRight Administrators $right
    foreach ($group in @(Get-AccountsWithUserRight $right)) {
        if (!($group -eq "Administrators")) {
        Revoke-UserRight $group $right
        }
    }
    

}

}

function listPorts {

    $TextBox1.appendtext("----------------List-Ports----------------")
	$TextBox1.appendtext("
")
    $TextBox1.appendtext("A list of active ports is to the right")
	$TextBox1.appendtext("
")
    $TextBox1.appendtext("Or if that turns out ugly run this command")
	$TextBox1.appendtext("
")
    $TextBox1.appendtext("Get-NetTCPConnection -State established")
	$TextBox1.appendtext("
")
   
    $APorts = Get-NetTCPConnection -State established
    $TextBox2.visible = $true
    
    foreach ($line in $APorts) {
        $TextBox2.appendtext($line)
        $TextBox2.appendtext("
")
    }
    Start-Process -FilePath Powershell -verb runas

}

###User Manager Functions

function GetAllUsers {

	$users2 = @(net users)
	$users3 = @()
	$users4 = @()
	$users5 = @()
	$AllUsers = @()
	$AllUsersText = @()

	foreach ($line in $users2) {

		if (!($line -eq "") -and !($line -match "-") -and !($line -match "User accounts for") -and !($line -match "The command completed")) {$users3 += $line}

	}

	foreach ($line in $users3) {

		$users4 += -split $line

	}

	foreach ($line in $users4) {

		if (!($line -eq " ")) {$users5 += $line}

	}

	foreach ($line in $users5) {

		if (!($line -eq "administrator") -and !($line -eq "cpadministrator") -and !($line -eq "guest") -and !($line -eq "cpguest")){$AllUsers += $line}

	}

	foreach ($line in $AllUsers) {

		$AllUsersText += $line
		$AllUsersText += "
"

	}

	$AllList.text =  $AllUsersText
	$Label3.text = "All Users"
	$Button7.visible = $true
	$Button10.visible = $false

	return $AllUsers
}


function CreateUsers  {

	$AllUsers = GetAllUsers
	$ConUsers =  ($ChangeUsers.text) -split "
"
	$UserOutput.appendtext("-----")
	$UserOutput.appendtext("
")

	foreach ($u in $ConUsers) {

			if ($u -in $AllUsers) 
			{ 

				$UserOutput.appendtext("A user called $u already exists")
				$UserOutput.appendtext("
")
			} else {

				try {New-LocalUser -name $u -NoPassword}
				catch {
					$UserOutput.appendtext("fuck fuck fuck it broke again kill me please")
					$UserOutput.appendtext("
")
				}
				$UserOutput.appendtext("Created a user called $u")
				$UserOutput.appendtext("
")
				}

		}
	GetAllUsers
	}


function AddAdmin  {

	$AllUsers = GetAllUsers
	$ConUsers =  ($ChangeUsers.text) -split "
"
	$UserOutput.appendtext("-----")
	$UserOutput.appendtext("
")
	$admins = (net localgroup administrators)
	foreach ($u in $ConUsers) {

		if ($u -in $admins) {

			$UserOutput.appendtext("$u is already an admin")
			$UserOutput.appendtext("
")
		} elseif ($u -notin $AllUsers) {

			$UserOutput.appendtext("There is no user called $u")
			$UserOutput.appendtext("
")			
		} else {
		
			Add-LocalGroupMember -Group Administrators -Member $u
			$UserOutput.appendtext("Made $u an admin")
			$UserOutput.appendtext("
")	
			}
	}
	pulladmins
}


function SetPasswords  {

	$AllUsers = GetAllUsers
	$ConUsers =  ($ChangeUsers.text) -split "
"
	$UserOutput.appendtext("-----")
	$UserOutput.appendtext("
")

	foreach ($u in $ConUsers) {

			if ($u -in $AllUsers) 
			{ 
				net user $u Password@69 /passwordchg:yes /passwordreq:yes
				$UserOutput.appendtext("Set password for $u")
				$UserOutput.appendtext("
")
			} else {

				$UserOutput.appendtext("There is no user called $u")
				$UserOutput.appendtext("
")
				}

		}
}


function DisableUsers  {

	$AllUsers = GetAllUsers
	$ConUsers =  ($ChangeUsers.text) -split "
"
	$UserOutput.appendtext("-----")
	$UserOutput.appendtext("
")

	
	foreach ($u in $ConUsers) {

			if ($u -in $AllUsers) 
			{ 
				net user $u /active:no
				$UserOutput.appendtext("$u has been disabled")
				$UserOutput.appendtext("
")
			} else {

				$UserOutput.appendtext("There is no user called $u")
				$UserOutput.appendtext("
")
				}

		}

}


function RemoveAdmins  {

	$AllUsers = GetAllUsers
	$ConUsers =  ($ChangeUsers.text) -split "
"
	$UserOutput.appendtext("-----")
	$UserOutput.appendtext("
")
	$admins = (net localgroup administrators)

	foreach ($u in $ConUsers) {

		if ($u -in $admins) {
			Remove-LocalGroupMember -Group Administrators -Member $u
			$UserOutput.appendtext("$u is no longer an admin")
			$UserOutput.appendtext("
")
		} elseif (!($u -in $AllUsers)) {

			$UserOutput.appendtext("There is no user called $u")
			$UserOutput.appendtext("
")			
		} else {
			
			$UserOutput.appendtext("$u is not an admin")
			$UserOutput.appendtext("
")	
			}
	}
	pulladmins
}


function PwNExpires  {

	$AllUsers = GetAllUsers
	$ConUsers =  ($ChangeUsers.text) -split "
"
	$UserOutput.appendtext("-----")
	$UserOutput.appendtext("
")
	foreach ($u in $ConUsers) {
		if ($u -notin $AllUsers) 
		{
			$UserOutput.appendtext("There is no user called $u")
			$UserOutput.appendtext("
")
		}

		elseif ((net user $u | findstr /c:"Password expires") -eq "Password expires              Never") 
		{
            Set-LocalUser -Name $u -PasswordNeverExpires $false
			$UserOutput.appendtext("disabled PASSWORDNEVEREXPIRES for $u")
			$UserOutput.appendtext("
")

		}
	}
}


function PullAdmins  {

	$AllUsers = GetAllUsers
	$admins = net localgroup administrators
	$admins2 = @()
	$adminslist = @()

	foreach ($line in $admins) {

		if (!($line -eq "") -and !($line -match "Alias") -and !($line -match "Members") -and !($line -match "-") -and !($line -match "Comment") -and !($line -match "complete")) {$admins2 += $line}

	}

	foreach ($line in $admins2) {

		$adminslist += $line
		$adminslist += "
"

	}

$AllList.text =  $adminslist
$Label3.text = "All Admins"
$Button7.visible = $false
$Button10.visible = $true

}


function Invert {


	$AllUsers = GetAllUsers
	$Results = @()
	$CUsers = @($ChangeUsers.text)
	foreach ($line in $AllUsers) {if ($line -in $CUsers){$Results += $line}}
	
	$ChangeUsers.text = ""

	foreach ($line in $Results) 
		{
			$UserOutput.appendtext($line)
			$UserOutput.appendtext(" ")
			$ChangeUsers.appendtext($line)
			$ChangeUsers.appendtext("
")
		}

$ChangeUsers.text = "god i fucking hate everything i need sleep"


	}


function AffectAllUsers {

	$AllUsers = GetAllUsers
	$ChangeUsers.text = ""
	foreach ($line in $AllUsers)
	{
		$ChangeUsers.appendtext($line)
		$ChangeUsers.appendtext("
")

	}

}



###Get all users


Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

###User Manager GUI

$UserGUI                         = New-Object system.Windows.Forms.Form
$UserGUI.WindowState             = 'Maximized'
$UserGUI.text                    = "User Manager"
$UserGUI.BackColor               = "#4a90e2"
$UserGUI.TopMost                 = $true

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Welcome to the User Manager"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(92,10)
$Label1.Font                     = 'Comic Sans MS,18'

$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "Users to Configure"
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(482,40)
$Label2.Font                     = 'Comic Sans MS,14'

$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "All Users"
$Label3.AutoSize                 = $true
$Label3.width                    = 25
$Label3.height                   = 10
$Label3.location                 = New-Object System.Drawing.Point(768,40)
$Label3.Font                     = 'Comic Sans MS,14'


$UserOutput                       = New-Object system.Windows.Forms.TextBox
$UserOutput.multiline             = $true
$UserOutput.ReadOnly              = $true
$UserOutput.WordWrap              = $true
$UserOutput.width                 = 400
$UserOutput.height                = 150
$UserOutput.location              = New-Object System.Drawing.Point(20,250)
$UserOutput.Font                  = 'Microsoft Sans Serif,10'
$UserOutput.Scrollbars            = "Vertical"

$ChangeUsers                     = New-Object system.Windows.Forms.TextBox
$ChangeUsers.multiline           = $true
$ChangeUsers.WordWrap            = $true
$ChangeUsers.width               = 200
$ChangeUsers.height              = 320
$ChangeUsers.location            = New-Object System.Drawing.Point(470,80)
$ChangeUsers.Font                = 'Microsoft Sans Serif,10'
$ChangeUsers.Scrollbars          = "Vertical"

$AllList                    = New-Object system.Windows.Forms.TextBox
$AllList.text               = $AllUsersText
$AllList.multiline          = $true
$AllList.WordWrap           = $true
$AllList.ReadOnly           = $true
$AllList.width              = 200
$AllList.height             = 320
$AllList.location           = New-Object System.Drawing.Point(720,80)
$AllList.Font               = 'Microsoft Sans Serif,10'
$AllList.Scrollbars         = "Vertical"

$Button1                         = New-Object system.Windows.Forms.Button
$Button1.text                    = "Create users"
$Button1.width                   = 90
$Button1.height                  = 40
$Button1.location                = New-Object System.Drawing.Point(20,80)
$Button1.Font                    = 'Microsoft Sans Serif,10'
$Button1.Add_Click({CreateUsers})

$Button2                         = New-Object system.Windows.Forms.Button
$Button2.text                    = "Add Admins"
$Button2.width                   = 90
$Button2.height                  = 40
$Button2.location                = New-Object System.Drawing.Point(20,140)
$Button2.Font                    = 'Microsoft Sans Serif,10'
$Button2.Add_Click({AddAdmin})

$Button3                         = New-Object system.Windows.Forms.Button
$Button3.text                    = "Set Passwords"
$Button3.width                   = 90
$Button3.height                  = 40
$Button3.location                = New-Object System.Drawing.Point(20,200)
$Button3.Font                    = 'Microsoft Sans Serif,10'
$Button3.Add_Click({SetPasswords})

$Button4                         = New-Object system.Windows.Forms.Button
$Button4.text                    = "Disable Users"
$Button4.width                   = 90
$Button4.height                  = 40
$Button4.location                = New-Object System.Drawing.Point(120,80)
$Button4.Font                    = 'Microsoft Sans Serif,10'
$Button4.Add_Click({DisableUsers})

$Button5                         = New-Object system.Windows.Forms.Button
$Button5.text                    = "Remove Admins"
$Button5.width                   = 90
$Button5.height                  = 40
$Button5.location                = New-Object System.Drawing.Point(120,140)
$Button5.Font                    = 'Microsoft Sans Serif,10'
$Button5.Add_Click({RemoveAdmins})

$Button6                         = New-Object system.Windows.Forms.Button
$Button6.text                    = "Disable PwNExpires"
$Button6.width                   = 90
$Button6.height                  = 40
$Button6.location                = New-Object System.Drawing.Point(120,200)
$Button6.Font                    = 'Microsoft Sans Serif,10'
$Button6.Add_Click({PwNExpires})

$Button7                         = New-Object system.Windows.Forms.Button
$Button7.text                    = "Pull Admins"
$Button7.width                   = 100
$Button7.height                  = 40
$Button7.location                = New-Object System.Drawing.Point(320,80)
$Button7.Font                    = 'Microsoft Sans Serif,10'
$Button7.Add_Click({PullAdmins})

$Button8                         = New-Object system.Windows.Forms.Button
$Button8.text                    = "Invert Users"
$Button8.width                   = 100
$Button8.height                  = 40
$Button8.location                = New-Object System.Drawing.Point(320,140)
$Button8.Font                    = 'Microsoft Sans Serif,10'
$Button8.Add_Click({Invert})

$Button9                         = New-Object system.Windows.Forms.Button
$Button9.text                    = "All Users"
$Button9.width                   = 100
$Button9.height                  = 40
$Button9.location                = New-Object System.Drawing.Point(320,200)
$Button9.Font                    = 'Microsoft Sans Serif,10'
$Button9.Add_Click({AffectAllUsers})

$Button10                         = New-Object system.Windows.Forms.Button
$Button10.visible                 = $false      
$Button10.text                    = "Pull Users"
$Button10.width                   = 100
$Button10.height                  = 40
$Button10.location                = New-Object System.Drawing.Point(320,80)
$Button10.Font                    = 'Microsoft Sans Serif,10'
$Button10.Add_Click({GetAllUsers})

$UserGUI.controls.AddRange(@($Label1,$Label2,$Label3,$UserOutput,$ChangeUsers,$AllList,$Button1,$Button2,$Button3,$Button4,$Button5,$Button6,$Button7,$Button8,$Button9,$Button10))


###Main GUI
$AugustusGUI                     = New-Object system.Windows.Forms.Form
$AugustusGUI.WindowState         = 'Maximized'
$AugustusGUI.text                = "Augustus GUI"
$AugustusGUI.BackColor           = "#4a90e2"

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Welcome to the Augustus GUI"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(92,33)
$Label1.Font                     = 'Comic Sans MS,18'

$CheckBox1                      = New-Object system.Windows.Forms.CheckBox
$CheckBox1.text                 = "File Dump"
$CheckBox1.AutoSize             = $true
$CheckBox1.width                = 95
$CheckBox1.height               = 20
$CheckBox1.location             = New-Object System.Drawing.Point(20,80)
$CheckBox1.Font                 = 'Microsoft Sans Serif,12'

$CheckBox2                       = New-Object system.Windows.Forms.CheckBox
$CheckBox2.text                  = "Rename Defaults"
$CheckBox2.AutoSize              = $true
$CheckBox2.width                 = 95
$CheckBox2.height                = 20
$CheckBox2.location              = New-Object System.Drawing.Point(20,110)
$CheckBox2.Font                  = 'Microsoft Sans Serif,12'

$CheckBox3                       = New-Object system.Windows.Forms.CheckBox
$CheckBox3.text                  = "Password Policy"
$CheckBox3.AutoSize              = $true
$CheckBox3.width                 = 95
$CheckBox3.height                = 20
$CheckBox3.location              = New-Object System.Drawing.Point(20,140)
$CheckBox3.Font                  = 'Microsoft Sans Serif,12'

$CheckBox4                       = New-Object system.Windows.Forms.CheckBox
$CheckBox4.text                  = "Auditing"
$CheckBox4.AutoSize              = $true
$CheckBox4.width                 = 95
$CheckBox4.height                = 20
$CheckBox4.location              = New-Object System.Drawing.Point(20,170)
$CheckBox4.Font                  = 'Microsoft Sans Serif,12'

$CheckBox5                       = New-Object system.Windows.Forms.CheckBox
$CheckBox5.text                  = "View Net Shares"
$CheckBox5.AutoSize              = $true
$CheckBox5.width                 = 95
$CheckBox5.height                = 20
$CheckBox5.location              = New-Object System.Drawing.Point(20,200)
$CheckBox5.Font                  = 'Microsoft Sans Serif,12'

$CheckBox6                       = New-Object system.Windows.Forms.CheckBox
$CheckBox6.text                  = "Clear Host File"
$CheckBox6.AutoSize              = $true
$CheckBox6.width                 = 95
$CheckBox6.height                = 20
$CheckBox6.location              = New-Object System.Drawing.Point(20,230)
$CheckBox6.Font                  = 'Microsoft Sans Serif,12'

$CheckBox7                       = New-Object system.Windows.Forms.CheckBox
$CheckBox7.text                  = "Weak Features"
$CheckBox7.AutoSize              = $true
$CheckBox7.width                 = 95
$CheckBox7.height                = 20
$CheckBox7.location              = New-Object System.Drawing.Point(20,260)
$CheckBox7.Font                  = 'Microsoft Sans Serif,12'

$CheckBox8                       = New-Object system.Windows.Forms.CheckBox
$CheckBox8.text                  = "Suspicious Tasks"
$CheckBox8.AutoSize              = $true
$CheckBox8.width                 = 95
$CheckBox8.height                = 20
$CheckBox8.location              = New-Object System.Drawing.Point(170,80)
$CheckBox8.Font                  = 'Microsoft Sans Serif,12'

$CheckBox9                       = New-Object system.Windows.Forms.CheckBox
$CheckBox9.text                  = "FireWall"
$CheckBox9.AutoSize              = $true
$CheckBox9.width                 = 95
$CheckBox9.height                = 20
$CheckBox9.location              = New-Object System.Drawing.Point(170,110)
$CheckBox9.Font                  = 'Microsoft Sans Serif,12'

$CheckBox10                       = New-Object system.Windows.Forms.CheckBox
$CheckBox10.text                  = "Disable Ports"
$CheckBox10.AutoSize              = $true
$CheckBox10.width                 = 95
$CheckBox10.height                = 20
$CheckBox10.location              = New-Object System.Drawing.Point(170,140)
$CheckBox10.Font                  = 'Microsoft Sans Serif,12'

$CheckBox11                      = New-Object system.Windows.Forms.CheckBox
$CheckBox11.text                 = "Disable RD"
$CheckBox11.AutoSize             = $true
$CheckBox11.width                = 95
$CheckBox11.height               = 20
$CheckBox11.location             = New-Object System.Drawing.Point(170,170)
$CheckBox11.Font                 = 'Microsoft Sans Serif,12'

$CheckBox12                      = New-Object system.Windows.Forms.CheckBox
$CheckBox12.text                 = "Auto Update"
$CheckBox12.AutoSize             = $true
$CheckBox12.width                = 95
$CheckBox12.height               = 20
$CheckBox12.location             = New-Object System.Drawing.Point(170,200)
$CheckBox12.Font                 = 'Microsoft Sans Serif,12'

$CheckBox13                      = New-Object system.Windows.Forms.CheckBox
$CheckBox13.text                 = "Secure Settings"
$CheckBox13.AutoSize             = $true
$CheckBox13.width                = 95
$CheckBox13.height               = 20
$CheckBox13.location             = New-Object System.Drawing.Point(170,230)
$CheckBox13.Font                 = 'Microsoft Sans Serif,12'

$CheckBox14                      = New-Object system.Windows.Forms.CheckBox
$CheckBox14.text                 = "Services"
$CheckBox14.AutoSize             = $true
$CheckBox14.width                = 95
$CheckBox14.height               = 20
$CheckBox14.location             = New-Object System.Drawing.Point(170,260)
$CheckBox14.Font                 = 'Microsoft Sans Serif,12'

$CheckBox15                      = New-Object system.Windows.Forms.CheckBox
$CheckBox15.text                 = "Scheduled Tasks"
$CheckBox15.AutoSize             = $true
$CheckBox15.width                = 95
$CheckBox15.height               = 20
$CheckBox15.location             = New-Object System.Drawing.Point(320,80)
$CheckBox15.Font                 = 'Microsoft Sans Serif,12'

$CheckBox16                      = New-Object system.Windows.Forms.CheckBox
$CheckBox16.text                 = "Helpful Programs"
$CheckBox16.AutoSize             = $true
$CheckBox16.width                = 95
$CheckBox16.height               = 20
$CheckBox16.location             = New-Object System.Drawing.Point(320,110)
$CheckBox16.Font                 = 'Microsoft Sans Serif,12'

$CheckBox17                      = New-Object system.Windows.Forms.CheckBox
$CheckBox17.text                 = "Create God Mode"
$CheckBox17.AutoSize             = $true
$CheckBox17.width                = 95
$CheckBox17.height               = 20
$CheckBox17.location             = New-Object System.Drawing.Point(320,140)
$CheckBox17.Font                 = 'Microsoft Sans Serif,12'

$CheckBox18                      = New-Object system.Windows.Forms.CheckBox
$CheckBox18.text                 = "Secure RDP"
$CheckBox18.AutoSize             = $true
$CheckBox18.width                = 95
$CheckBox18.height               = 20
$CheckBox18.location             = New-Object System.Drawing.Point(320,170)
$CheckBox18.Font                 = 'Microsoft Sans Serif,12'

$CheckBox19                      = New-Object system.Windows.Forms.CheckBox
$CheckBox19.text                 = "DEL Default Apps"
$CheckBox19.AutoSize             = $true
$CheckBox19.width                = 95
$CheckBox19.height               = 20
$CheckBox19.location             = New-Object System.Drawing.Point(320,200)
$CheckBox19.Font                 = 'Microsoft Sans Serif,12'

$CheckBox20                      = New-Object system.Windows.Forms.CheckBox
$CheckBox20.text                 = "User Rights"
$CheckBox20.AutoSize             = $true
$CheckBox20.width                = 95
$CheckBox20.height               = 20
$CheckBox20.location             = New-Object System.Drawing.Point(320,230)
$CheckBox20.Font                 = 'Microsoft Sans Serif,12'

$CheckBox21                      = New-Object system.Windows.Forms.CheckBox
$CheckBox21.text                 = "List Ports"
$CheckBox21.AutoSize             = $true
$CheckBox21.width                = 95
$CheckBox21.height               = 20
$CheckBox21.location             = New-Object System.Drawing.Point(320,260)
$CheckBox21.Font                 = 'Microsoft Sans Serif,12'

$TextBox1                        = New-Object system.Windows.Forms.TextBox
$TextBox1.multiline              = $true
$TextBox1.ReadOnly               = $true
$TextBox1.WordWrap               = $true
$TextBox1.width                  = 550
$TextBox1.height                 = 120
$TextBox1.location               = New-Object System.Drawing.Point(20,300)
$TextBox1.Font                   = 'Microsoft Sans Serif,10'
$TextBox1.Scrollbars             = "Vertical"


$TextBox2                        = New-Object system.Windows.Forms.TextBox
$TextBox2.multiline              = $true
$TextBox2.ReadOnly               = $true
$TextBox2.WordWrap               = $true
$TextBox2.visible                = $false
$TextBox2.width                  = 700
$TextBox2.height                 = 341
$TextBox2.location               = New-Object System.Drawing.Point(600,80)
$TextBox2.Font                   = 'Microsoft Sans Serif,10'
$TextBox2.Scrollbars             = "Vertical"

$Button2                         = New-Object system.Windows.Forms.Button
$Button2.text                    = "Exit"
$Button2.width                   = 90
$Button2.height                  = 40
$Button2.location                = New-Object System.Drawing.Point(480,130)
$Button2.Font                    = 'Microsoft Sans Serif,10'
$Button2.Add_Click({$AugustusGUI.close()})

$Button3                         = New-Object system.Windows.Forms.Button
$Button3.text                    = "Clear"
$Button3.width                   = 90
$Button3.height                  = 40
$Button3.location                = New-Object System.Drawing.Point(480,180)
$Button3.Font                    = 'Microsoft Sans Serif,10'
$Button3.Add_Click(
	{
		$textbox1.text = ""
		$textbox2.text = ""
		$UserOutput.text = ""
		$AllList.text = ""
		$ChangeUsers.text = ""
}

)

$Button4                         = New-Object system.Windows.Forms.Button
$Button4.text                    = "Failed attempt"
$Button4.width                   = 90
$Button4.height                  = 40
$Button4.location                = New-Object System.Drawing.Point(480,230)
$Button4.Font                    = 'Microsoft Sans Serif,10'
$Button4.Add_Click(
	{
		GetAllUsers
		[void]$UserGUI.ShowDialog()	
	}
)

$Button1                         = New-Object system.Windows.Forms.Button
$Button1.text                    = "Configure"
$Button1.width                   = 90
$Button1.height                  = 40
$Button1.location                = New-Object System.Drawing.Point(480,80)
$Button1.Font                    = 'Microsoft Sans Serif,10'
$Button1.Add_Click(
    {   

if ($CheckBox1.checked -eq $true) {
	$CheckBox1.checked = $false
	filedump
}

if ($CheckBox2.checked -eq $true) {
	$CheckBox2.checked = $false
	RenameDfts
}

if ($CheckBox3.checked -eq $true) {
	$CheckBox3.checked = $false
	passPol
}

if ($CheckBox4.checked -eq $true) {
	$CheckBox4.checked = $false
	auditPol
}

if ($CheckBox5.checked -eq $true) {
	$CheckBox5.checked = $false
	netShare
}

if ($CheckBox6.checked -eq $true) {
	$CheckBox6.checked = $false
	hosts
}

if ($CheckBox7.checked -eq $true) {
	$CheckBox7.checked = $false
	weakServices
}

if ($CheckBox8.checked -eq $true) {
	$CheckBox8.checked = $false
	processes
}

if ($CheckBox9.checked -eq $true) {
	$CheckBox9.checked = $false
	firewall
}

if ($CheckBox10.checked -eq $true) {
	$CheckBox10.checked = $false
	ports
}

if ($CheckBox11.checked -eq $true) {
	$CheckBox11.checked = $false
	remoteDesktop
}

if ($CheckBox12.checked -eq $true) {
	$CheckBox12.checked = $false
	autoUpdate
}

if ($CheckBox13.checked -eq $true) {
	$CheckBox13.checked = $false
	secOpt
}

if ($CheckBox14.checked -eq $true) {
	$CheckBox14.checked = $false
	services
}

if ($CheckBox15.checked -eq $true) {
	$CheckBox15.checked = $false
	scheduledTasks
}

if ($CheckBox16.checked -eq $true) {
	$CheckBox16.checked = $false
	programs
}

if ($CheckBox17.checked -eq $true) {
	$CheckBox17.checked = $false
	godmode
}

if ($CheckBox18.checked -eq $true) {
	$CheckBox18.checked = $false
	SecureANDenableRDP
}

if ($CheckBox19.checked -eq $true) {
	$CheckBox19.checked = $false
	removeDefaultApps
}

if ($CheckBox20.checked -eq $true) {
	$CheckBox20.checked = $false
	UserRights
}

if ($CheckBox21.checked -eq $true) {
	$CheckBox21.checked = $false
	listPorts
}

    }
)

$AugustusGUI.controls.AddRange(@($Label1,$CheckBox1,$CheckBox2,$CheckBox3,$CheckBox4,$CheckBox5,$CheckBox6,$CheckBox7,$CheckBox8,$CheckBox9,$CheckBox10,$CheckBox11,$CheckBox12,$CheckBox13,$CheckBox14,$CheckBox15,$CheckBox16,$CheckBox17,$CheckBox18,$CheckBox19,$CheckBox20,$CheckBox21,$Button1,$TextBox1,$Button2,$TextBox2,$Button3,$Button4))

[void]$AugustusGUI.ShowDialog()
















































































