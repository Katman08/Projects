@echo off

echo Checking if script was launched with Admin permissions...

net sessions
if %errorlevel%==0 (
    echo Success!
) else (
    echo No admin, restarting with Administrative rights...
	powershell -Command "Start-Process ./Augustus.bat -Verb RunAs"
	exit
)
PAUSE

cls

:MENU
CLS
ECHO REMINDER: README FIRST!!!
ECHO
ECHO ========= Augustus Toolkit ==========
ECHO -------------------------------------
ECHO 1.  Password Policy
ECHO 2.  AuditPolicy
ECHO 3.  Security Options
ECHO 4.  Rename Accounts
ECHO 5.  Firewall
ECHO 6.  Services
ECHO 7.  Updates
ECHO 8.  Shares
ECHO 9.  Disable Remote Desktop
ECHO 10. Find Media Files
ECHO 11. Set Services
ECHO 12. Flush DNS + Clean Hosts
ECHO 13. User Config
ECHO 14. Standby
ECHO 15. User Properties
ECHO 16. Change Passwords
ECHO 17. Disable Guest and Admin
ECHO 18. Disable Auto Run
ECHO -------------------------------------
ECHO ==========PRESS 'Q' TO QUIT==========
ECHO.

SET INPUT=
SET /P INPUT=Please select a number:

IF /I '%INPUT%'=='1' GOTO PasswordPolicy
IF /I '%INPUT%'=='2' GOTO AuditPolicy
IF /I '%INPUT%'=='3' GOTO SecurityOptions
IF /I '%INPUT%'=='4' GOTO RenameAccounts
IF /I '%INPUT%'=='5' GOTO Firewall
IF /I '%INPUT%'=='6' GOTO Services
IF /I '%INPUT%'=='7' GOTO Updates
IF /I '%INPUT%'=='8' GOTO Shares
IF /I '%INPUT%'=='9' GOTO RemoteDesktop
IF /I '%INPUT%'=='10' GOTO MediaFiles
IF /I '%INPUT%'=='11' GOTO Services
IF /I '%INPUT%'=='12' GOTO FlushDNS
IF /I '%INPUT%'=='13' GOTO UserConfig
IF /I '%INPUT%'=='14' GOTO Standby
IF /I '%INPUT%'=='15' GOTO UserProp
IF /I '%INPUT%'=='16' GOTO ChngPass
IF /I '%INPUT%'=='17' GOTO DisGuestAdmin
IF /I '%INPUT%'=='18' GOTO DisAutoRun
IF /I '%INPUT%'=='Q' GOTO Quit

CLS

ECHO ============INVALID INPUT============
ECHO -------------------------------------
ECHO Please select a number from the Main
echo Menu [1-9] or select 'Q' to quit.
ECHO -------------------------------------
ECHO ======PRESS ANY KEY TO CONTINUE======

PAUSE > NUL
GOTO MENU

REM --------------------------------------------------------------------------------------------------

:PasswordPolicy
REM Password Policy
echo "Current Password Policy:"
net accounts

echo "Changing Password Policy:"

REM Enforce Password History (5)
net accounts /UNIQUEPW:5

REM Max Password Age (30)
net accounts /MAXPWAGE:30

REM Min Password Age (5)
net accounts /MINPWAGE:5

REM Minimum Password Length (10)
net accounts /MINPWLEN:10

echo "Password Policy Changed"

REM Account Lockout Policy
echo "Changing Account Lockout Policy..."

REM Lockout Duration (30)
net accounts /LOCKOUTDURATION:30

REM Lockout Threshold (5)
net accounts /LOCKOUTTHRESHOLD:5

REM Reset Account Lockout After (30)
net accounts /LOCKOUTWINDOW:30

echo "The Rest Of The Settings Must Be Configured Manually, Opening SECPOL.MSC"
echo "Please Configure The Following:"
echo "Password Complecity [Enabled]"
echo "Store Using Reversible Encryption [Disabled]"

start SECPOL.MSC

PAUSE
goto MENU

goto ViewPassPol

REM --------------------------------------------------------------------------------------------------

:AuditPolicy
Echo "Changing Audit Policy"

REM Audit Logon Events Failure
Auditpol /set /category:"Account Logon" /failure:enable

REM Audit Account Management Success
Auditpol /set /category:"Account Management" /Success:enable 

REM Audit logon Events Failure
Auditpol /set /category:"Logon/Logoff" /failure:enable

REM Audit Policy Change Success
Auditpol /set /category:"policy change" /Success:enable 

REM Audit Privilege use success failure
Auditpol /set /category:"Privilege use" /Success:enable /failure:enable

REM Audit Process tracking Success Failure BROKEN
Auditpol /set /category:"process tracking" /Success:enable /failure:enable

REM Audit System Events failure
Auditpol /set /category:"System" /failure:enable

PAUSE
goto MENU

REM --------------------------------------------------------------------------------------------------

:SecurityOptions

echo Changing security options now.

rem Restrict CD ROM drive
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

rem Automatic Admin logon
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
	
rem Logon message text
set /p body=Please enter logon text: 
    reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticetext" /v LegalNoticeText /t REG_SZ /d "%body%"
	
rem Logon message title bar
set /p subject=Please enter the title of the message: 
	reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticecaption" /v LegalNoticeCaption /t REG_SZ /d "%subject%"
	
rem Wipe page file from shutdown
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
	
rem Disallow remote access to floppie disks
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
	
rem Prevent print driver installs 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
	
rem Limit local account use of blank passwords to console
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
	
rem Auditing access of Global System Objects
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
	
rem Auditing Backup and Restore
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
	
rem Do not display last user on logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
	
rem UAC setting (Prompt on Secure Desktop)
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
	
rem Enable Installer Detection
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
	
rem Undock without logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
	
rem Maximum Machine Password Age
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
	
rem Disable machine account password changes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
	
rem Require Strong Session Key
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
	
rem Require Sign/Seal
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
	
rem Sign Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
	
rem Seal Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
	
rem Don't disable CTRL+ALT+DEL even though it serves no purpose
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f 
	
rem Restrict Anonymous Enumeration #1
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
	
rem Restrict Anonymous Enumeration #2
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f 
	
rem Idle Time Limit - 45 mins
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f 
	
rem Require Security Signature - Disabled pursuant to checklist
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f 
	
rem Enable Security Signature - Disabled pursuant to checklist
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f 
	
rem Disable Domain Credential Storage
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f 
	
rem Don't Give Anons Everyone Permissions
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
	
rem SMB Passwords unencrypted to third party
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
	
rem Null Session Pipes Cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
	
rem remotely accessible registry paths cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
	
rem remotely accessible registry paths and sub-paths cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
	
rem Restict anonymous access to named pipes and shares
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
	
rem Allow to use Machine ID for NTLM
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f

rem Enables DEP
bcdedit.exe /set {current} nx AlwaysOn

PAUSE 
goto MENU

REM --------------------------------------------------------------------------------------------------

:Firewall
Echo "Querying Firewall State..."
Netsh Advfirewall show allprofiles

Echo "Verifying Firewall Is Enabled"
NetSh Advfirewall set allprofiles state on

PAUSE
goto MENU

REM --------------------------------------------------------------------------------------------------

:Updates
ECHO "Enabling automatic updates..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f

ECHO "Starting wuauserv..."
sc config wuauserv start= auto
net start wuauserv

PAUSE
goto MENU

REM --------------------------------------------------------------------------------------------------

:Shares
ECHO "Outputting Shares List"
net share

PAUSE
goto MENU

REM --------------------------------------------------------------------------------------------------

:RemoteDesktop
REM Disable Remote Desktop
echo "Disabling Remote Destkop..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

PAUSE
goto MENU

REM --------------------------------------------------------------------------------------------------

:MediaFiles
dir /s/d *.mp3 && *.ac3 && *.aac && *.aiff && *.flac && *.m4a && *.m4p && *.midi && *.mp2 && *.m3u && *.ogg && *.vqf && *.wav 
dir /s/d *.wma && *.mp4 && *.avi && *.mpeg4
dir /s/d *.gif && *.png && *.bmp && *.jpg && *.jpeg && *.mov && *.mpv

PAUSE
goto MENU

REM --------------------------------------------------------------------------------------------------

:Services
SET ServicesDisable = wisvc WMPNetworkSvc ALG NfsClnt MapsBroker irmon SharedAccess SmsRouter WpcMonSvc PhoneSvc RetailDemo RpcLocator icssvc WinRM WwanSvc XblAuthManager XblGameSave XboxNetApiSvc RemoteRegistry RemoteAccess TapiSrv Tlntsvr tlntsvr p2pimsvc simptcp fax msftpsvc iprip ftpsvc RemoteRegistry RasMan RasAuto seclogon MSFTPSVC W3SVC SMTPSVC Dfs TrkWks MSDTC DNS ERSVC NtFrs MSFtpsvc helpsvc HTTPFilter IISADMIN IsmServ WmdmPmSN Spooler RDSessMgr RPCLocator RsoPProv ShellHWDetection ScardSvr Sacsvr TermService Uploadmgr VDS VSS WINS WinHttpAutoProxySvc SZCSVC CscService hidserv IPBusEnum PolicyAgent SCPolicySvc SharedAccess SSDPSRV Themes upnphost nfssvc nfsclnt MSSQLServerADHelper
SET ServicesManual = dmserver SrvcSurg
SET ServicesAuto = Dhcp Dnscache NtLmSsp

echo Disabling Weak Services...
for %%a in (%servicesD%) do (
	echo Service: %%a
	sc stop "%%a"
	sc config "%%a" start= disabled
)
echo Disabled bad services

echo Setting services to manual...
for %%b in (%ServicesManual%) do (
	echo Service: %%b
	sc config "%%b" start= demand
)
echo Set services to manual

echo Seting services to auto...
for %%c in (%ServicesAuto%) do (
	echo Service: %%c
	sc config "%%c" start= auto
)
echo Started auto services

PAUSE
goto MENU

REM --------------------------------------------------------------------------------------------------

:FlushDNS
echo "Flushing DNS..."
ipconfig /flushdns > nul
echo "Flushed DNS"

echo "Clearing contents of: C:\Windows\System32\drivers\etc\hosts"
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
attrib +r +s C:\WINDOWS\system32\drivers\etc\hosts
echo "Cleared hosts file"
goto MENU

REM --------------------------------------------------------------------------------------------------

:RenameAccounts
echo Disabling Administrator account...
net user Administrator /active:no && (
	echo Disabled administrator account
	(call)
) || echo Administrator account not disabled

echo Disabling Guest account...
net user Guest /active:no && (
	echo Disabled Guest account
	(call)
) || echo Guest account not disabled

echo Disabled guest account
echo Renaming Administrator to "CPAdmin" and Guest to "CPGuest"
start C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%path%resources\RenameDefAccounts.ps1"
echo Renamed Administrator to "CPAdmin" and Guest to "CPGuest"

PAUSE
goto MENU

REM --------------------------------------------------------------------------------------------------

:UserConfig

%path%/subscripts/user-config.ps1

PAUSE 
goto MENU

REM --------------------------------------------------------------------------------------------------

:standby

powercfg /x -standby-timeout-dc 10
powercfg /x -standby-timeout-ac 10
powercfg /x monitor-timeout-ac 10
powercfg /x monitor-timeout-dc 10

PAUSE
goto MENU

REM --------------------------------------------------------------------------------------------------

:UserProp

echo Setting password never expires
wmic UserAccount set PasswordExpires=True	
wmic UserAccount set PasswordChangeable=True
wmic UserAccount set PasswordRequired=True

pause
goto MENU

REM --------------------------------------------------------------------------------------------------

:ChngPass

echo Changing all user passwords
	
endlocal
setlocal EnableExtensions
for /F "tokens=2* delims==" %%G in ('
	wmic UserAccount where "status='ok'" get name >null
') do for %%g in (%%~G) do (
    net user %%~g Password*19
)
endlocal
setlocal enabledelayedexpansion	
pause
goto MENU

REM --------------------------------------------------------------------------------------------------

:DisGuestAdmin

rem Disables the guest account
net user Guest | findstr Active | findstr Yes
if %errorlevel%==0 (
	echo Guest account is already disabled.
)
if %errorlevel%==1 (
	net user guest CPGuest /active:no
)
	
rem Disables the Admin account
net user Administrator | findstr Active | findstr Yes

if %errorlevel%==0 (
	echo Admin account is already disabled.
	pause
	goto MENU
)

if %errorlevel%==1 (
	net user administrator CPGuest /active:no
	pause
	goto MENU
)

REM --------------------------------------------------------------------------------------------------

:DisAutoRun
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f

REM --------------------------------------------------------------------------------------------------
