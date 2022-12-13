$arrayargs = [System.Collections.ArrayList]::new()
$Privileges = $null
$Sleep = 0
$SleepInBlock = 0
$LogPath = $null

if($args.Count -gt 0){
    for($count = 0; $args.Count -gt $count; $count++){
        [void]$arrayargs.Add( $args[$count] )
    }
}

 # Privilege check
 function CheckAdmin{
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) 
    Start-Sleep -seconds $SleepInBlock

    if($isAdmin -eq [bool]$True){
        $Privileges = "Administrator"
        Start-Sleep -seconds $SleepInBlock
    }
    else{
        $Privileges = "User"
        Start-Sleep -seconds $SleepInBlock
    }

    Write-Host "`n===== Access level is: $Privileges =====`n`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function SysInfo{
    Write-Host "[*] Basic System Information..." -ForegroundColor black -BackgroundColor white
    systeminfo
    Write-Host "`t[?] Check system information`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function SystemDate{
    Write-Host "[*] Date test Started" -ForegroundColor black -BackgroundColor white
    $Date = Get-Date
    Write-Host "`t[*] $Date" -ForegroundColor Yellow
    Write-Host "`t[?] Check the date and time`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function EnvVariables{
    Write-Host "[*] Scan environment variables..." -ForegroundColor black -BackgroundColor white
    Get-ChildItem Env: | Format-Table Key,Value
    Write-Host "`t[?] Check the environment variables`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function NetInfo{
    Write-Host "[*] Get Net IP Configuration..." -ForegroundColor black -BackgroundColor white
    Get-NetIPConfiguration | Format-Table InterfaceAlias, InterfaceDescription, IPv4Address
    Write-Host "`t[?] Check the network information`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function DNSinfo{
    Write-Host "[*] Get DNS server IP addresses from the TCP/IP properties on an interface..." -ForegroundColor black -BackgroundColor white
    Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table
    Write-Host "`t[?] Check DNS info`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function MountedDisks{
    Write-Host "[*] Gets drives in the current session..." -ForegroundColor black -BackgroundColor white
    Get-PSDrive | Where-Object {
        $_.Provider -like "Microsoft.PowerShell.Core\FileSystem" } | Format-Table
    Write-Host "`t[?] Check Mounted Disks`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}
function Firewall{
    Write-Host "[*] Get firewall show config..." -ForegroundColor black -BackgroundColor white
    Start-Process "netsh" -ArgumentList "firewall show config" -NoNewWindow -Wait | Format-Table
    Write-Host "`t[?] Check firewall config`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function CurrentUser{
    Write-Host "[*] Get current user..." -ForegroundColor black -BackgroundColor white
    Write-Host "$env:UserDomain\$env:UserName"
    Write-Host "`t[?] Check Current Users`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function LocalUsers{
    Write-Host "[*] Get local users..." -ForegroundColor black -BackgroundColor white
    Get-LocalUser | Format-Table Name,Enabled,LastLogon
    Write-Host "`t[?] Check local users`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function UserPrivileges{
    Write-Host "[*] Get user privileges... " -ForegroundColor black -BackgroundColor white
    Start-Process "whoami" -ArgumentList "/priv" -NoNewWindow -Wait | Format-Table
    Write-Host "`t[?] Check user privileges`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function LoggedUsers{
    Write-Host "[*] Get logged in users..." -ForegroundColor black -BackgroundColor white
    Start-Process "qwinsta" -NoNewWindow -Wait | Format-Table
    Write-Host "`t[?] Check logged in users`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function AutoLogon{
    Write-Host "[*] Get user autologon registry items..." -ForegroundColor black -BackgroundColor white
    Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | Select-Object "Default*" | Format-Table
    Write-Host "`t[?] Check user autologon registry items`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function LocalGroups{
    Write-Host "[*] Get local groups..." -ForegroundColor black -BackgroundColor white
    Get-LocalGroup | Format-Table Name
    Write-Host "`t[?] Check local groups`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function LocalAdmin{
    Write-Host "[*] Detection of system Administrators" -ForegroundColor black -BackgroundColor white

    $Language = (Get-UICulture).name
    if($Language -like "ru-*"){
        Get-LocalGroupMember Администраторы | Format-Table Name, PrincipalSource
    }
    elseif($Language -like "en-*"){
        Get-LocalGroupMember Administrators | Format-Table Name, PrincipalSource
    }
    else{
        Write-Host ""`t[!] The language of the system differs from "ru" and "en", there may be errors in identifying users with Administrator privileges`n`n"" -ForegroundColor Red
        Start-Sleep -seconds $SleepInBlock
        Get-LocalGroupMember Administrators | Format-Table Name, PrincipalSource
    }
    Write-Host "`t[?] Check the list of users with Administrator privileges`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function UserDirectories{
    Write-Host "[*] Get user directories..." -ForegroundColor black -BackgroundColor white
    Get-ChildItem C:\Users | Format-Table Name
    Write-Host "`t[?] Check user directories`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function Cred{
    Write-Host "[*] Get credential manager..." -ForegroundColor black -BackgroundColor white
    start-process "cmdkey" -ArgumentList "/list" -NoNewWindow -Wait | Format-Table
    Write-Host "`t[?] Check credential manager`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function SAMBackupFiles{
    Write-Host "[*] Searching for SAM backup files..." -ForegroundColor black -BackgroundColor white
    $PathFlag1 = Test-Path %SYSTEMROOT%\repair\SAM  
    $PathFlag2 = Test-Path %SYSTEMROOT%\system32\config\regback\SAM 
    if($PathFlag1 -eq $True){
        Write-Host "`t[!] SAM backup files found in %SYSTEMROOT%\system32\config\regback\SAM`n`n" -ForegroundColor Red
    }
    if($PathFlag2 -eq $True){
        Write-Host "`t[!] SAM backup files found in %SYSTEMROOT%\system32\config\regback\SAM`n`n" -ForegroundColor Red
    }
    if(($PathFlag1 -eq $False) -and ($PathFlag1 -eq $False)){
        Write-Host "`t[+] SAM backup files not found`n`n" -ForegroundColor Green
    }
    else{
        Write-Host "`t[*] SAM backup files have been found, it should be fixed`n`n" -ForegroundColor Yellow
    }
    Start-Sleep -seconds $Sleep
}

function RunningProcesses{
    Write-Host "[*] Get running processes..." -ForegroundColor black -BackgroundColor white
    Get-WmiObject -Query "Select * from Win32_Process" | Where-Object {
        $_.Name -notlike "svchost*"} | Select-Object Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}
    } | Format-Table -AutoSize
    Write-Host "`t[?] Check running processes`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function InstalledSoftwareDir{
    Write-Host "[*] Get directory of installed software..." -ForegroundColor black -BackgroundColor white
    Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | Format-Table Parent,Name,LastWriteTime
    Write-Host "`t[?] Check directory of installed software`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function RegSoftware{
    Write-Host "[*] Get software in registry..." -ForegroundColor black -BackgroundColor white
    Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | Format-Table Name
    Write-Host "`t[?] Check software in registry`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function EveryonePermissions{
    Write-Host "[*] Get folders with everyone permissions..." -ForegroundColor black -BackgroundColor white
    $EveryonePermissions = Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | ForEach-Object { 
        try { Get-Acl $_ -EA SilentlyContinue | Where-Object {($_.Access|Select-Object -ExpandProperty IdentityReference) -match "Everyone"} }
        catch { } 
    }| Format-Table
    if($EveryonePermissions -ne $null){
        Write-Host  "$EveryonePermissions"
        Write-Host "`t[!] Check folders with everyone permissions`n`n" -ForegroundColor Red
    }
    else {
        Write-Host "`t[+] Folders with access rights for everyone in 'C:\Program Files\*' and 'C:\Program Files (x86)\*' were not found`n`n" -ForegroundColor Green
    }
    Start-Sleep -seconds $Sleep
}

function BUILTIN{
    Write-Host "[*] Get folders with BUILTIN\user permissions..." -ForegroundColor black -BackgroundColor white
    $BUILTINFlag = $False
    $BUILTIN = Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | ForEach-Object { 
        try { Get-Acl $_ -EA SilentlyContinue | Where-Object {($_.Access|Select-Object -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } 
        catch { } 
    } | Format-Table
    if($BUILTIN -ne $null){
        Write-Host  "$BUILTIN"
        Write-Host "`t[!] Check folders with BUILTIN\User permissions`n`n" -ForegroundColor Red
    }
    else {
        Write-Host "`t[+] Folders with access permissions for BUILTIN\user in 'C:\Program Files\*' and 'C:\Program Files (x86)\*' were not found`n`n" -ForegroundColor Green
    }
    Start-Sleep -seconds $Sleep
}

function AlwaysInstallElevated{
    Write-Host "[*] Checking registry for Always install elevated..." -ForegroundColor black -BackgroundColor white
    $AlwaysInstallElevated = Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer" | Format-Table
    if($AlwaysInstallElevated -eq $True){
        Write-Host "`t[*] Check 'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer'" -ForegroundColor Red
        Write-Host "`t[!] Always installable elevated registry found`n`n"                                    -ForegroundColor Red
    }
    else{
        Write-Host "`t[+] Always installable elevated registry not found`n`n" -ForegroundColor Green
    }
    Start-Sleep -seconds $Sleep
}

function UnqServPaths{
    Write-Host "[*] Get Unquoted Service Paths..." -ForegroundColor black -BackgroundColor white
    $UnqServPaths = Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where-Object { 
        $_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'
    } | Select-Object PathName, DisplayName, Name | Format-Table
    if($UnqServPaths -ne $null){
        $UnqServPaths
        Write-Host "`t[?] You should check the service paths without quotes`n`n" -ForegroundColor Yellow
    }
    else{
        Write-Host "`t[+] Service paths without quotes were not found`n`n" -ForegroundColor Green
    }
    Start-Sleep -seconds $Sleep
}

function ScheduledTasks{
    Write-Host "[*] Get scheduled tasks..." -ForegroundColor black -BackgroundColor white
    Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | Format-Table TaskName,TaskPath,State
    Write-Host "`t[?] Check scheduled tasks`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function TasksFolder{
    Write-Host "[*] Get tasks folder..." -ForegroundColor black -BackgroundColor white
    Get-ChildItem C:\Windows\Tasks | Format-Table
    Write-Host "`t[?] Check tasks folder`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function StartupCommands{
    Write-Host "[*] Get startup commands..." -ForegroundColor black -BackgroundColor white
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List
    Write-Host "`t[?] Check startup commands`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function HotFixes{
    Write-Host "[*] HotFixes test Started" -ForegroundColor black -BackgroundColor white

    $HFflag = $False
    Start-Sleep -seconds $SleepInBlock
    $HotFixes = wmic qfe get HotFixID 
    Start-Sleep -seconds $SleepInBlock

    if ( systeminfo | findstr /i "2000 XP 2003 2008 vista" ) { $HFflag = $True; Write-Host "`t[!] Vulns: Old OS version" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock

    if ( $HotFixes | findstr /C:"KB2592799" ) { $HFflag = $True; Write-Host "`t[!] Vulns: XP/SP3,2K3/SP3-afd.sys" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB3143141" ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB2393802" ) { $HFflag = $True; Write-Host "`t[!] Vulns: XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB982799"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K8,Vista,7/SP0-Chimichurri" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB979683"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB2305420" ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB981957"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB4013081" ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB977165"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K,XP,2K3,2K8,Vista,7-User Mode to Ring" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB941693"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB920958"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K/SP4-ZwQuerySysInfo" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB914389"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K,XP/SP2-Mrxsmb.sys" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB908523"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K/SP4-APC Data-Free" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB890859"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K/SP3/4,XP/SP1/2-CSRSS" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB842526"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K/SP2/3/4-Utility Manager" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB835732"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K/SP2/3/4,XP/SP0/1-LSASS service BoF" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB841872"  ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K/SP4-POSIX" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB2975684" ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB3136041" ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB3057191" ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB2989935" ) { $HFflag = $True; Write-Host "`t[!] Vulns: 2K3/SP2-TCP/IP" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB2778930" ) { $HFflag = $True; Write-Host "`t[!] Vulns: Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB2850851" ) { $HFflag = $True; Write-Host "`t[!] Vulns: 7SP0/SP1_x86-schlamperei" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock
    if ( $HotFixes | findstr /C:"KB2870008" ) { $HFflag = $True; Write-Host "`t[!] Vulns: 7SP0/SP1_x86-track_popup_menu" -ForegroundColor Red }
    Start-Sleep -seconds $SleepInBlock

    if     ( $HFflag -eq $False )  { Write-Host "`t[+] HotFixes test passed`n`n"        -ForegroundColor Green }
    elseif ( $HFflag -eq $True  )  { Write-Host "`n`t[!] HotFixes test found Vulns`n`n" -ForegroundColor Red   }
    Start-Sleep -seconds $Sleep
}

function NETVersion{
    Write-Host "[*] .NETVersion test Started" -ForegroundColor black -BackgroundColor white
    Write-Host "`t[?] Installed .NET Framework versions: " -ForegroundColor Yellow

    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
                Get-ItemProperty -name Version, Release -EA 0                 |
                Where-Object { $_.PSChildName -match '^(?!S)\p{L}'}           |
                Select-Object @{name = ".NET Framework"; expression = {$_.PSChildName}}, Version

    Write-Host
    Start-Sleep -seconds $Sleep
}

function PSVersion{
    $PSVersion = $PSVersionTable.PSVersion.Major
    Write-Host "[*] Checking for Default PowerShell version ..." -ForegroundColor black -BackgroundColor white
    Start-Sleep -seconds $SleepInBlock

    if(($PSVersion -lt 2) -or ($PSVersion -gt 5.1)){
        Write-Warning  "[!] You have PowerShell v$PSVersion.`n"
        Write-Warning  "[!] This script only supports Powershell verion not less than 2 and not more than 5.1.`n`n"
        Start-Sleep -seconds $Sleep
        Read-Host
        exit
    }
    if($PSVersion -eq 5){
        Write-Host "`t[+] PowerShell v$PSVersion`n`n"  -ForegroundColor Green
        Start-Sleep -seconds $Sleep
    }
}

function SystemRole{
    [int]$systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
    #$RoleIDflag = $False
    $systemRoles = @{
                    0 = " Standalone Workstation    " ;
                    1 = " Member Workstation        " ;
                    2 = " Standalone Server         " ;
                    3 = " Member Server             " ;
                    4 = " Backup  Domain Controller " ;
                    5 = " Primary Domain Controller "       
                    }

    
    Write-Host "[*] Detecting system role ..." -ForegroundColor black -BackgroundColor white
    Start-Sleep -seconds $SleepInBlock

    Write-Host "`t[?]",$systemRoles[[int]$systemRoleID],"`n`n" -ForegroundColor Yellow
    Start-Sleep -seconds $Sleep
}

function ProxyDetect{   
    Write-Host "[*] Searching for network proxy..." -ForegroundColor black -BackgroundColor white

    $reg2 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $env:COMPUTERNAME)
    $regkey2 = $reg2.OpenSubkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
    Start-Sleep -seconds $SleepInBlock

    if ($regkey2.GetValue('ProxyServer') -and $regkey2.GetValue('ProxyEnable'))
    {
        $proxy = Read-Host -Prompt 'Proxy detected! Proxy is: '$regkey2.GetValue('ProxyServer')'! Does the Powershell-User have proxy rights? (yes/no)'
        if ($proxy -eq "yes" -or $proxy -eq "y" -or $proxy -eq "Yes" -or $proxy -eq "Y")
        {
            Write-Host 'Setting up Powershell-Session Proxy Credentials...' -ForegroundColor Yellow
            $Wcl = new-object System.Net.WebClient
            $Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            Start-Sleep -seconds $SleepInBlock
        }
        else
        {
            Write-Host '=== Please enter valid credentials, or the script will fail! ===' -ForegroundColor Yellow 
            #Proxy Integration manual user
            $webclient = New-Object System.Net.WebClient
            $creds = Get-Credential
            $webclient.Proxy.Credentials = $creds
            Start-Sleep -seconds $SleepInBlock
        }
    }
    else 
    {
        Write-Host "`t[?] No proxy detected, continuing... " -ForegroundColor Yellow 
    }
    Write-Host
    Start-Sleep -seconds $Sleep
}

function AuditSettings{
    Write-Host "[*] AuditSettings test Started..." -ForegroundColor black -BackgroundColor white
    start-sleep -seconds $SleepInBlock
    
    Get-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
    
    Write-Host "`t[?] Check AuditSettings`n" -ForegroundColor Yellow
}

function Antivirus { 
    Write-Host "[*] Search for installed antivirus..." -ForegroundColor black -BackgroundColor white
    $wmiQuery = "SELECT * FROM AntiVirusProduct" 
    $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psBoundParameters
    [array]$AntivirusNames = $AntivirusProduct.displayName
    Switch($AntivirusNames) {
        {$AntivirusNames.Count -eq 0}                                {Write-Host "`t[!] Anti-Virus is NOT installed!`n`n"        -ForegroundColor Red;    Continue}
        {$AntivirusNames.Count -eq 1 -and $_ -eq "Windows Defender"} {Write-Host "`t[*] ONLY Windows Defender is installed!`n`n" -ForegroundColor Yellow; Continue}
        {$_ -ne "Windows Defender"}                                  {Write-Host "`t[+] Anti-Virus is installed ($_).`n`n"       -ForegroundColor Green}
    }
}

function PathCheck{
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName   
    Write-Host "[*] Creating/Checking Log Folders in '$currentPath' directory:" -ForegroundColor black -BackgroundColor white
    
    if(!(Test-Path -Path $currentPath\LocalRecon\))      {mkdir $currentPath\LocalRecon\}
    if(!(Test-Path -Path $currentPath\DomainRecon\))     {mkdir $currentPath\DomainRecon\; mkdir $currentPath\DomainRecon\ADrecon}
    if(!(Test-Path -Path $currentPath\LocalPrivEsc\))    {mkdir $currentPath\LocalPrivEsc\}
    if(!(Test-Path -Path $currentPath\Exploitation\))    {mkdir $currentPath\Exploitation\}
    if(!(Test-Path -Path $currentPath\Vulnerabilities\)) {mkdir $currentPath\Vulnerabilities\}
    if(!(Test-Path -Path $currentPath\LocalPrivEsc\))    {mkdir $currentPath\LocalPrivEsc\}
    
    Write-Host "`t[+] Path Check Completed`n" -ForegroundColor Green
}

function FindSpooler{
    Write-Host "[?] Spooler test Started" -ForegroundColor black -BackgroundColor white

    if((Get-Service -Name Spooler | Where-Object -Property Status -eq -Value 'running')){ 
        Write-Host "`t[!] Attention: The print manager may not be secure to this day"    -ForegroundColor Red
        Write-Host "`t[?] Check out the threat fixes CVE-2021-1675 and CVE-2021-34527`n" -ForegroundColor Yellow
        Start-Sleep -seconds $Sleep

        Get-Service -Name Spooler | Select-Object Name, Status, CanShutdown, CanStop, DisplayName, StartType | Format-Table

        Start-Sleep -seconds $Sleep
        Write-Host "`tYou can disable the Print Spooler service "                                                                          -ForegroundColor Yellow
        Write-Host "`tIf disabling the Print Spooler service is appropriate for your enterprise, use the following PowerShell commands:"   -ForegroundColor Yellow
        Write-Host "`tStop-Service -Name Spooler -Force"                                                                                   -ForegroundColor black -BackgroundColor white
        Write-Host "`tSet-Service  -Name Spooler -StartupType Disabled"                                                                    -ForegroundColor black -BackgroundColor white
        Write-Host "`tImpact of workaround Disabling the Print Spooler service disables the ability to print both locally and remotely.`n" -ForegroundColor Yellow
        Start-Sleep -seconds $Sleep
    }
    else{
        Write-Host "`t[?] Attention: The print manager may not be secure to this day"  -ForegroundColor Yellow
        Write-Host "`t[?] Check out the threat fixes CVE-2021-1675 and CVE-2021-34527" -ForegroundColor Yellow
        Get-Service -Name Spooler | Select-Object Name, Status, DisplayName, StartType | Format-Table
        Start-Sleep -seconds $Sleep
    }
}

if('all' -in $ArrayArgs){
    Write-Host "The program is running in full test mode, all tests will be performed"

    if($LogPath -ne $null) { CheckAdmin >> $LogPath } else{ CheckAdmin }
    if($LogPath -ne $null) { SysInfo >> $LogPath } else{ SysInfo }
    if($LogPath -ne $null) { MountedDisks >> $LogPath } else{ MountedDisks }
    if($LogPath -ne $null) { SystemDate >> $LogPath } else{ SystemDate }
    if($LogPath -ne $null) { NETVersion >> $LogPath } else{ NETVersion }
    if($LogPath -ne $null) { PSVersion >> $LogPath } else{ PSVersion }
    if($LogPath -ne $null) { SystemRole >> $LogPath } else{ SystemRole }
    if($LogPath -ne $null) { ProxyDetect >> $LogPath } else{ ProxyDetect }
    if($LogPath -ne $null) { AuditSettings >> $LogPath } else{ AuditSettings }
    if($LogPath -ne $null) { EnvVariables >> $LogPath } else{ EnvVariables }

    if($LogPath -ne $null) { NetInfo >> $LogPath } else{ NetInfo }
    if($LogPath -ne $null) { DNSinfo >> $LogPath } else{ DNSinfo }
    if($LogPath -ne $null) { Firewall >> $LogPath } else{ Firewall }

    if($LogPath -ne $null) { LoggedUsers >> $LogPath } else{ LoggedUsers }
    if($LogPath -ne $null) { CurrentUser >> $LogPath } else{ CurrentUser }
    if($LogPath -ne $null) { UserPrivileges >> $LogPath } else{ UserPrivileges }
    if($LogPath -ne $null) { LocalUsers >> $LogPath } else{ LocalUsers }
    if($LogPath -ne $null) { LocalGroups >> $LogPath } else{ LocalGroups }
    if($LogPath -ne $null) { LocalAdmin >> $LogPath } else{ LocalAdmin }
    if($LogPath -ne $null) { AutoLogon >> $LogPath } else{ AutoLogon }
    if($LogPath -ne $null) { UserDirectories >> $LogPath } else{ UserDirectories }
    if($LogPath -ne $null) { Cred >> $LogPath } else{ Cred }
    if($LogPath -ne $null) { SAMBackupFiles >> $LogPath } else{ SAMBackupFiles }

    if($LogPath -ne $null) { RunningProcesses >> $LogPath } else{ RunningProcesses }

    if($LogPath -ne $null) { InstalledSoftwareDir >> $LogPath } else{ InstalledSoftwareDir }
    if($LogPath -ne $null) { RegSoftware >> $LogPath } else{ RegSoftware }
    if($LogPath -ne $null) { UnqServPaths >> $LogPath } else{ UnqServPaths }

    if($LogPath -ne $null) { AlwaysInstallElevated >> $LogPath } else{ AlwaysInstallElevated }
    if($LogPath -ne $null) { EveryonePermissions >> $LogPath } else{ EveryonePermissions }
    if($LogPath -ne $null) { BUILTIN >> $LogPath } else{ BUILTIN }

    if($LogPath -ne $null) { StartupCommands >> $LogPath } else{ StartupCommands }
    if($LogPath -ne $null) { ScheduledTasks >> $LogPath } else{ ScheduledTasks }
    if($LogPath -ne $null) { TasksFolder >> $LogPath } else{ TasksFolder }

    if($LogPath -ne $null) { HotFixes >> $LogPath } else{ HotFixes }
    if($LogPath -ne $null) { Antivirus >> $LogPath } else{ Antivirus }
    if($LogPath -ne $null) { PathCheck >> $LogPath } else{ PathCheck }
    if($LogPath -ne $null) { FindSpooler >> $LogPath } else{ FindSpooler }

}
else{
    if('Info' -in $ArrayArgs){
        Write-Host "[*] System Information:`n`n" -ForegroundColor black -BackgroundColor white

        if($LogPath -ne $null) { CheckAdmin >> $LogPath } else{ CheckAdmin }
        if($LogPath -ne $null) { SysInfo >> $LogPath } else{ SysInfo }
        if($LogPath -ne $null) { MountedDisks >> $LogPath } else{ MountedDisks }
        if($LogPath -ne $null) { SystemDate >> $LogPath } else{ SystemDate }
        if($LogPath -ne $null) { NETVersion >> $LogPath } else{ NETVersion }
        if($LogPath -ne $null) { PSVersion >> $LogPath } else{ PSVersion }
        if($LogPath -ne $null) { SystemRole >> $LogPath } else{ SystemRole }
        if($LogPath -ne $null) { ProxyDetect >> $LogPath } else{ ProxyDetect }
        if($LogPath -ne $null) { AuditSettings >> $LogPath } else{ AuditSettings }
        if($LogPath -ne $null) { EnvVariables >> $LogPath } else{ EnvVariables }
    }
    
    if('Network' -in $ArrayArgs){
        Write-Host "[*] Network Information:`n`n" -ForegroundColor black -BackgroundColor white

        if($LogPath -ne $null) { NetInfo >> $LogPath } else{ NetInfo }
        if($LogPath -ne $null) { DNSinfo >> $LogPath } else{ DNSinfo }
        if($LogPath -ne $null) { Firewall >> $LogPath } else{ Firewall }
    }
    
    if('Users' -in $ArrayArgs){
    Write-Host "[*] Users Information:`n`n" -ForegroundColor black -BackgroundColor white

    if($LogPath -ne $null) { LoggedUsers >> $LogPath } else{ LoggedUsers }
    if($LogPath -ne $null) { CurrentUser >> $LogPath } else{ CurrentUser }
    if($LogPath -ne $null) { UserPrivileges >> $LogPath } else{ UserPrivileges }
    if($LogPath -ne $null) { LocalUsers >> $LogPath } else{ LocalUsers }
    if($LogPath -ne $null) { LocalGroups >> $LogPath } else{ LocalGroups }
    if($LogPath -ne $null) { LocalAdmin >> $LogPath } else{ LocalAdmin }
    if($LogPath -ne $null) { AutoLogon >> $LogPath } else{ AutoLogon }
    if($LogPath -ne $null) { UserDirectories >> $LogPath } else{ UserDirectories }
    if($LogPath -ne $null) { Cred >> $LogPath } else{ Cred }
    if($LogPath -ne $null) { SAMBackupFiles >> $LogPath } else{ SAMBackupFiles }
    }
    
    if('Software' -in $ArrayArgs){
    Write-Host "[*] Software Information:`n`n" -ForegroundColor black -BackgroundColor white

    if($LogPath -ne $null) { InstalledSoftwareDir >> $LogPath } else{ InstalledSoftwareDir }
    if($LogPath -ne $null) { RegSoftware >> $LogPath } else{ RegSoftware }
    if($LogPath -ne $null) { UnqServPaths >> $LogPath } else{ UnqServPaths }
    }
    
    if('FPermissions' -in $ArrayArgs){
        Write-Host "[*] Forgotten Permissions Information:`n`n" -ForegroundColor black -BackgroundColor white

        if($LogPath -ne $null) { AlwaysInstallElevated >> $LogPath } else{ AlwaysInstallElevated }
        if($LogPath -ne $null) { EveryonePermissions >> $LogPath } else{ EveryonePermissions }
        if($LogPath -ne $null) { BUILTIN >> $LogPath } else{ BUILTIN }
    }
    
    if('Tasks' -in $ArrayArgs){
    Write-Host "[*] Tasks Information:`n`n" -ForegroundColor black -BackgroundColor white

    if($LogPath -ne $null) { StartupCommands >> $LogPath } else{ StartupCommands }
    if($LogPath -ne $null) { ScheduledTasks >> $LogPath } else{ ScheduledTasks }
    if($LogPath -ne $null) { TasksFolder >> $LogPath } else{ TasksFolder }
    }
    
    if('Other' -in $ArrayArgs){
        if($LogPath -ne $null) { HotFixes >> $LogPath } else{ HotFixes }
        if($LogPath -ne $null) { Antivirus >> $LogPath } else{ Antivirus }
        if($LogPath -ne $null) { PathCheck >> $LogPath } else{ PathCheck }
        if($LogPath -ne $null) { FindSpooler >> $LogPath } else{ FindSpooler }
    }

    if ( 'CheckAdmin' -in $ArrayArgs){ if($LogPath -ne $null) { CheckAdmin >> $LogPath } else{ CheckAdmin } }
    if ( 'SysInfo' -in $ArrayArgs){ if($LogPath -ne $null) { SysInfo >> $LogPath } else{ SysInfo } }
    if ( 'MountedDisks' -in $ArrayArgs){ if($LogPath -ne $null) { MountedDisks >> $LogPath } else{ MountedDisks } }
    if ( 'SystemDate' -in $ArrayArgs){ if($LogPath -ne $null) { SystemDate >> $LogPath } else{ SystemDate } }
    if ( 'NETVersion' -in $ArrayArgs){ if($LogPath -ne $null) { NETVersion >> $LogPath } else{ NETVersion } }
    if ( 'PSVersion' -in $ArrayArgs){ if($LogPath -ne $null) { PSVersion >> $LogPath } else{ PSVersion } }
    if ( 'SystemRole' -in $ArrayArgs){ if($LogPath -ne $null) { SystemRole >> $LogPath } else{ SystemRole } }
    if ( 'ProxyDetect' -in $ArrayArgs){ if($LogPath -ne $null) { ProxyDetect >> $LogPath } else{ ProxyDetect } }
    if ( 'AuditSettings' -in $ArrayArgs){ if($LogPath -ne $null) { AuditSettings >> $LogPath } else{ AuditSettings } }
    if ( 'EnvVariables' -in $ArrayArgs){ if($LogPath -ne $null) { EnvVariables >> $LogPath } else{ EnvVariables } }
    if ( 'NetInfo' -in $ArrayArgs){ if($LogPath -ne $null) { NetInfo >> $LogPath } else{ NetInfo } }
    if ( 'DNSinfo' -in $ArrayArgs){ if($LogPath -ne $null) { DNSinfo >> $LogPath } else{ DNSinfo } }
    if ( 'Firewall' -in $ArrayArgs){ if($LogPath -ne $null) { Firewall >> $LogPath } else{ Firewall } }
    if ( 'LoggedUsers' -in $ArrayArgs){ if($LogPath -ne $null) { LoggedUsers >> $LogPath } else{ LoggedUsers } }
    if ( 'CurrentUser' -in $ArrayArgs){ if($LogPath -ne $null) { CurrentUser >> $LogPath } else{ CurrentUser } }
    if ( 'UserPrivileges' -in $ArrayArgs){ if($LogPath -ne $null) { UserPrivileges >> $LogPath } else{ UserPrivileges } }
    if ( 'LocalUsers' -in $ArrayArgs){ if($LogPath -ne $null) { LocalUsers >> $LogPath } else{ LocalUsers } }
    if ( 'LocalGroups' -in $ArrayArgs){ if($LogPath -ne $null) { LocalGroups >> $LogPath } else{ LocalGroups } }
    if ( 'LocalAdmin' -in $ArrayArgs){ if($LogPath -ne $null) { LocalAdmin >> $LogPath } else{ LocalAdmin } }
    if ( 'AutoLogon' -in $ArrayArgs){ if($LogPath -ne $null) { AutoLogon >> $LogPath } else{ AutoLogon } }
    if ( 'UserDirectories' -in $ArrayArgs){ if($LogPath -ne $null) { UserDirectories >> $LogPath } else{ UserDirectories } }
    if ( 'Cred' -in $ArrayArgs){ if($LogPath -ne $null) { Cred >> $LogPath } else{ Cred } }
    if ( 'SAMBackupFiles' -in $ArrayArgs){ if($LogPath -ne $null) { SAMBackupFiles >> $LogPath } else{ SAMBackupFiles } }
    if ( 'RunningProcesses' -in $ArrayArgs){ if($LogPath -ne $null) { RunningProcesses >> $LogPath } else{ RunningProcesses } }
    if ( 'InstalledSoftwareDir' -in $ArrayArgs) { if($LogPath -ne $null) { InstalledSoftwareDir >> $LogPath } else{ InstalledSoftwareDir } }
    if ( 'RegSoftware' -in $ArrayArgs){ if($LogPath -ne $null) { RegSoftware >> $LogPath } else{ RegSoftware } }
    if ( 'UnqServPaths' -in $ArrayArgs){ if($LogPath -ne $null) { UnqServPaths >> $LogPath } else{ UnqServPaths } }
    if ( 'AlwaysInstallElevated' -in $ArrayArgs){ if($LogPath -ne $null) { AlwaysInstallElevated >> $LogPath } else{ AlwaysInstallElevated } }
    if ( 'EveryonePermissions' -in $ArrayArgs){ if($LogPath -ne $null) { EveryonePermissions >> $LogPath } else{ EveryonePermissions } }
    if ( 'BUILTIN' -in $ArrayArgs){ if($LogPath -ne $null) { BUILTIN >> $LogPath } else{ BUILTIN } }
    if ( 'StartupCommands' -in $ArrayArgs){ if($LogPath -ne $null) { StartupCommands >> $LogPath } else{ StartupCommands } }
    if ( 'ScheduledTasks' -in $ArrayArgs){ if($LogPath -ne $null) { ScheduledTasks >> $LogPath } else{ ScheduledTasks } }
    if ( 'TasksFolder' -in $ArrayArgs){ if($LogPath -ne $null) { TasksFolder >> $LogPath } else{ TasksFolder } }
    if ( 'HotFixes' -in $ArrayArgs){ if($LogPath -ne $null) { HotFixes >> $LogPath } else{ HotFixes } }
    if ( 'Antivirus' -in $ArrayArgs){ if($LogPath -ne $null) { Antivirus >> $LogPath } else{ Antivirus } }
    if ( 'PathCheck' -in $ArrayArgs){ if($LogPath -ne $null) { PathCheck >> $LogPath } else{ PathCheck } }
    if ( 'FindSpooler' -in $ArrayArgs){ if($LogPath -ne $null) { FindSpooler >> $LogPath } else{ FindSpooler } }
}

if($ArrayArgs.Count -eq 0){
    $NeedDelay = Read-Host "Do you need a delay between function execution? (By default NO)"
    switch -wildcard ($NeedDelay){
        'y*'    { $ReadSleep = Read-Host "The delay time between the execution of functions?" }
        'n*'    { $ReadSleep = [int]0 }
        Default { $ReadSleep = [int]0 }
    }
    $Sleep = [int]$ReadSleep

    $NeedDelayInBlock = Read-Host "Do you need a delay between the execution of parts of functions? (By default NO)"
    switch -wildcard ($NeedDelayInBlock){
        'y*'    { $ReadSleepInBlock = Read-Host "The delay time between the execution of parts of functions?" }
        'n*'    { $ReadSleepInBlock = [int]0 }
        Default { $ReadSleepInBlock = [int]0 }
    }
    $SleepInBlock = [int]$ReadSleepInBlock

    $Output = Read-Host "To output to the console or to a file? (By default to the console)"
    switch -wildcard ($Output) {
        '*f*'   { $ReadPath = Read-Host "Enter the file name .txt" }
        '*c*'   { }
        Default { }
    }
    $LogPath = $ReadPath


    $NewArrayArgs = [System.Collections.ArrayList]::new()
    
    $AllArgs = @('', 'all [2 - 8]', 'Info [9 - 18]', 'Network [19 - 21]', 'Users [22 - 31]', 
                 'Software [32 - 34]', 'FPermissions [35 - 37]', 'Tasks [38 - 40]', 'Other [41 - 45]', 
                 'CheckAdmin', 'SysInfo', 'MountedDisks', 'SystemDate', 'NETVersion', 
                 'PSVersion', 'SystemRole', 'ProxyDetect', 'AuditSettings', 'EnvVariables', 
                 'NetInfo', 'DNSinfo', 'Firewall', 'LoggedUsers', 'CurrentUser', 
                 'UserPrivileges', 'LocalUsers', 'LocalGroups', 'LocalAdmin', 'AutoLogon', 
                 'UserDirectories', 'Cred', 'SAMBackupFiles', 'InstalledSoftwareDir', 
                 'RegSoftware', 'UnqServPaths', 'AlwaysInstallElevated', 'EveryonePermissions', 'BUILTIN', 
                 'StartupCommands', 'ScheduledTasks', 'TasksFolder', 'RunningProcesses', 'HotFixes', 'Antivirus', 
                 'PathCheck', 'FindSpooler')
    
    ForEach($Modes in $AllArgs){
    $ModeIndex = [array]::IndexOf($AllArgs, $Modes)
    Write-Host "  " $ModeIndex $Modes
    }

    $arrayInput = Read-Host "Select the mode(s) separated by a space"
    $arrayInput = $arrayInput.Split(' ')
    
    foreach($element in $arrayInput){ 
        if(([int]$element -le ($AllArgs.Count - 1)) -and ([int]$element -ge 0)) { $NewArrayArgs += $AllArgs[$element] }
        else { } 
    }

    if('all [2 - 8]' -in $NewArrayArgs){
        Write-Host "The program is running in full test mode, all tests will be performed"

        if($LogPath -ne $null) { CheckAdmin >> $LogPath } else{ CheckAdmin }
        if($LogPath -ne $null) { SysInfo >> $LogPath } else{ SysInfo }
        if($LogPath -ne $null) { MountedDisks >> $LogPath } else{ MountedDisks }
        if($LogPath -ne $null) { SystemDate >> $LogPath } else{ SystemDate }
        if($LogPath -ne $null) { NETVersion >> $LogPath } else{ NETVersion }
        if($LogPath -ne $null) { PSVersion >> $LogPath } else{ PSVersion }
        if($LogPath -ne $null) { SystemRole >> $LogPath } else{ SystemRole }
        if($LogPath -ne $null) { ProxyDetect >> $LogPath } else{ ProxyDetect }
        if($LogPath -ne $null) { AuditSettings >> $LogPath } else{ AuditSettings }
        if($LogPath -ne $null) { EnvVariables >> $LogPath } else{ EnvVariables }

        if($LogPath -ne $null) { NetInfo >> $LogPath } else{ NetInfo }
        if($LogPath -ne $null) { DNSinfo >> $LogPath } else{ DNSinfo }
        if($LogPath -ne $null) { Firewall >> $LogPath } else{ Firewall }

        if($LogPath -ne $null) { LoggedUsers >> $LogPath } else{ LoggedUsers }
        if($LogPath -ne $null) { CurrentUser >> $LogPath } else{ CurrentUser }
        if($LogPath -ne $null) { UserPrivileges >> $LogPath } else{ UserPrivileges }
        if($LogPath -ne $null) { LocalUsers >> $LogPath } else{ LocalUsers }
        if($LogPath -ne $null) { LocalGroups >> $LogPath } else{ LocalGroups }
        if($LogPath -ne $null) { LocalAdmin >> $LogPath } else{ LocalAdmin }
        if($LogPath -ne $null) { AutoLogon >> $LogPath } else{ AutoLogon }
        if($LogPath -ne $null) { UserDirectories >> $LogPath } else{ UserDirectories }
        if($LogPath -ne $null) { Cred >> $LogPath } else{ Cred }
        if($LogPath -ne $null) { SAMBackupFiles >> $LogPath } else{ SAMBackupFiles }

        if($LogPath -ne $null) { RunningProcesses >> $LogPath } else{ RunningProcesses }

        if($LogPath -ne $null) { InstalledSoftwareDir >> $LogPath } else{ InstalledSoftwareDir }
        if($LogPath -ne $null) { RegSoftware >> $LogPath } else{ RegSoftware }
        if($LogPath -ne $null) { UnqServPaths >> $LogPath } else{ UnqServPaths }

        if($LogPath -ne $null) { AlwaysInstallElevated >> $LogPath } else{ AlwaysInstallElevated }
        if($LogPath -ne $null) { EveryonePermissions >> $LogPath } else{ EveryonePermissions }
        if($LogPath -ne $null) { BUILTIN >> $LogPath } else{ BUILTIN }

        if($LogPath -ne $null) { StartupCommands >> $LogPath } else{ StartupCommands }
        if($LogPath -ne $null) { ScheduledTasks >> $LogPath } else{ ScheduledTasks }
        if($LogPath -ne $null) { TasksFolder >> $LogPath } else{ TasksFolder }

        if($LogPath -ne $null) { HotFixes >> $LogPath } else{ HotFixes }
        if($LogPath -ne $null) { Antivirus >> $LogPath } else{ Antivirus }
        if($LogPath -ne $null) { PathCheck >> $LogPath } else{ PathCheck }
        if($LogPath -ne $null) { FindSpooler >> $LogPath } else{ FindSpooler }
    }
    else{
        if('Info [9 - 18]' -in $NewArrayArgs){
            Write-Host "[*] System Information:`n`n" -ForegroundColor black -BackgroundColor white

            if($LogPath -ne $null) { CheckAdmin >> $LogPath } else{ CheckAdmin }
            if($LogPath -ne $null) { SysInfo >> $LogPath } else{ SysInfo }
            if($LogPath -ne $null) { MountedDisks >> $LogPath } else{ MountedDisks }
            if($LogPath -ne $null) { SystemDate >> $LogPath } else{ SystemDate }
            if($LogPath -ne $null) { NETVersion >> $LogPath } else{ NETVersion }
            if($LogPath -ne $null) { PSVersion >> $LogPath } else{ PSVersion }
            if($LogPath -ne $null) { SystemRole >> $LogPath } else{ SystemRole }
            if($LogPath -ne $null) { ProxyDetect >> $LogPath } else{ ProxyDetect }
            if($LogPath -ne $null) { AuditSettings >> $LogPath } else{ AuditSettings }
            if($LogPath -ne $null) { EnvVariables >> $LogPath } else{ EnvVariables }
        }
        
        if('Network [19 - 21]' -in $NewArrayArgs){
            Write-Host "[*] Network Information:`n`n" -ForegroundColor black -BackgroundColor white

            if($LogPath -ne $null) { NetInfo >> $LogPath } else{ NetInfo }
            if($LogPath -ne $null) { DNSinfo >> $LogPath } else{ DNSinfo }
            if($LogPath -ne $null) { Firewall >> $LogPath } else{ Firewall }
        }
        
        if('Users [22 - 31]' -in $NewArrayArgs){
        Write-Host "[*] Users Information:`n`n" -ForegroundColor black -BackgroundColor white

        if($LogPath -ne $null) { LoggedUsers >> $LogPath } else{ LoggedUsers }
        if($LogPath -ne $null) { CurrentUser >> $LogPath } else{ CurrentUser }
        if($LogPath -ne $null) { UserPrivileges >> $LogPath } else{ UserPrivileges }
        if($LogPath -ne $null) { LocalUsers >> $LogPath } else{ LocalUsers }
        if($LogPath -ne $null) { LocalGroups >> $LogPath } else{ LocalGroups }
        if($LogPath -ne $null) { LocalAdmin >> $LogPath } else{ LocalAdmin }
        if($LogPath -ne $null) { AutoLogon >> $LogPath } else{ AutoLogon }
        if($LogPath -ne $null) { UserDirectories >> $LogPath } else{ UserDirectories }
        if($LogPath -ne $null) { Cred >> $LogPath } else{ Cred }
        if($LogPath -ne $null) { SAMBackupFiles >> $LogPath } else{ SAMBackupFiles }
        }
        
        if('Software [32 - 34]' -in $NewArrayArgs){
        Write-Host "[*] Software Information:`n`n" -ForegroundColor black -BackgroundColor white

        if($LogPath -ne $null) { InstalledSoftwareDir >> $LogPath } else{ InstalledSoftwareDir }
        if($LogPath -ne $null) { RegSoftware >> $LogPath } else{ RegSoftware }
        if($LogPath -ne $null) { UnqServPaths >> $LogPath } else{ UnqServPaths }
        }
        
        if('FPermissions [35 - 37]' -in $NewArrayArgs){
            Write-Host "[*] Forgotten Permissions Information:`n`n" -ForegroundColor black -BackgroundColor white

            if($LogPath -ne $null) { AlwaysInstallElevated >> $LogPath } else{ AlwaysInstallElevated }
            if($LogPath -ne $null) { EveryonePermissions >> $LogPath } else{ EveryonePermissions }
            if($LogPath -ne $null) { BUILTIN >> $LogPath } else{ BUILTIN }
        }
        
        if('Tasks [38 - 40]' -in $NewArrayArgs){
        Write-Host "[*] Tasks Information:`n`n" -ForegroundColor black -BackgroundColor white

        if($LogPath -ne $null) { StartupCommands >> $LogPath } else{ StartupCommands }
        if($LogPath -ne $null) { ScheduledTasks >> $LogPath } else{ ScheduledTasks }
        if($LogPath -ne $null) { TasksFolder >> $LogPath } else{ TasksFolder }
        }
        
        if('Other [41 - 45]' -in $NewArrayArgs){

            if( 'RunningProcesses' -in $NewArrayArgs ){ RunningProcesses }
            if( 'HotFixes' -in $NewArrayArgs ){ HotFixes }
            if( 'Antivirus' -in $NewArrayArgs ){ Antivirus }
            if( 'PathCheck' -in $NewArrayArgs ){ PathCheck }
            if( 'FindSpooler' -in $NewArrayArgs ){ FindSpooler }

        }
        
        if ( 'CheckAdmin' -in $NewArrayArgs){ if($LogPath -ne $null) { CheckAdmin >> $LogPath } else{ CheckAdmin } }
        if ( 'SysInfo' -in $NewArrayArgs){ if($LogPath -ne $null) { SysInfo >> $LogPath } else{ SysInfo } }
        if ( 'MountedDisks' -in $NewArrayArgs){ if($LogPath -ne $null) { MountedDisks >> $LogPath } else{ MountedDisks } }
        if ( 'SystemDate' -in $NewArrayArgs){ if($LogPath -ne $null) { SystemDate >> $LogPath } else{ SystemDate } }
        if ( 'NETVersion' -in $NewArrayArgs){ if($LogPath -ne $null) { NETVersion >> $LogPath } else{ NETVersion } }
        if ( 'PSVersion' -in $NewArrayArgs){ if($LogPath -ne $null) { PSVersion >> $LogPath } else{ PSVersion } }
        if ( 'SystemRole' -in $NewArrayArgs){ if($LogPath -ne $null) { SystemRole >> $LogPath } else{ SystemRole } }
        if ( 'ProxyDetect' -in $NewArrayArgs){ if($LogPath -ne $null) { ProxyDetect >> $LogPath } else{ ProxyDetect } }
        if ( 'AuditSettings' -in $NewArrayArgs){ if($LogPath -ne $null) { AuditSettings >> $LogPath } else{ AuditSettings } }
        if ( 'EnvVariables' -in $NewArrayArgs){ if($LogPath -ne $null) { EnvVariables >> $LogPath } else{ EnvVariables } }
        if ( 'NetInfo' -in $NewArrayArgs){ if($LogPath -ne $null) { NetInfo >> $LogPath } else{ NetInfo } }
        if ( 'DNSinfo' -in $NewArrayArgs){ if($LogPath -ne $null) { DNSinfo >> $LogPath } else{ DNSinfo } }
        if ( 'Firewall' -in $NewArrayArgs){ if($LogPath -ne $null) { Firewall >> $LogPath } else{ Firewall } }
        if ( 'LoggedUsers' -in $NewArrayArgs){ if($LogPath -ne $null) { LoggedUsers >> $LogPath } else{ LoggedUsers } }
        if ( 'CurrentUser' -in $NewArrayArgs){ if($LogPath -ne $null) { CurrentUser >> $LogPath } else{ CurrentUser } }
        if ( 'UserPrivileges' -in $NewArrayArgs){ if($LogPath -ne $null) { UserPrivileges >> $LogPath } else{ UserPrivileges } }
        if ( 'LocalUsers' -in $NewArrayArgs){ if($LogPath -ne $null) { LocalUsers >> $LogPath } else{ LocalUsers } }
        if ( 'LocalGroups' -in $NewArrayArgs){ if($LogPath -ne $null) { LocalGroups >> $LogPath } else{ LocalGroups } }
        if ( 'LocalAdmin' -in $NewArrayArgs){ if($LogPath -ne $null) { LocalAdmin >> $LogPath } else{ LocalAdmin } }
        if ( 'AutoLogon' -in $NewArrayArgs){ if($LogPath -ne $null) { AutoLogon >> $LogPath } else{ AutoLogon } }
        if ( 'UserDirectories' -in $NewArrayArgs){ if($LogPath -ne $null) { UserDirectories >> $LogPath } else{ UserDirectories } }
        if ( 'Cred' -in $NewArrayArgs){ if($LogPath -ne $null) { Cred >> $LogPath } else{ Cred } }
        if ( 'SAMBackupFiles' -in $NewArrayArgs){ if($LogPath -ne $null) { SAMBackupFiles >> $LogPath } else{ SAMBackupFiles } }
        if ( 'RunningProcesses' -in $NewArrayArgs){ if($LogPath -ne $null) { RunningProcesses >> $LogPath } else{ RunningProcesses } }
        if ( 'InstalledSoftwareDir' -in $NewArrayArgs) { if($LogPath -ne $null) { InstalledSoftwareDir >> $LogPath } else{ InstalledSoftwareDir } }
        if ( 'RegSoftware' -in $NewArrayArgs){ if($LogPath -ne $null) { RegSoftware >> $LogPath } else{ RegSoftware } }
        if ( 'UnqServPaths' -in $NewArrayArgs){ if($LogPath -ne $null) { UnqServPaths >> $LogPath } else{ UnqServPaths } }
        if ( 'AlwaysInstallElevated' -in $NewArrayArgs){ if($LogPath -ne $null) { AlwaysInstallElevated >> $LogPath } else{ AlwaysInstallElevated } }
        if ( 'EveryonePermissions' -in $NewArrayArgs){ if($LogPath -ne $null) { EveryonePermissions >> $LogPath } else{ EveryonePermissions } }
        if ( 'BUILTIN' -in $NewArrayArgs){ if($LogPath -ne $null) { BUILTIN >> $LogPath } else{ BUILTIN } }
        if ( 'StartupCommands' -in $NewArrayArgs){ if($LogPath -ne $null) { StartupCommands >> $LogPath } else{ StartupCommands } }
        if ( 'ScheduledTasks' -in $NewArrayArgs){ if($LogPath -ne $null) { ScheduledTasks >> $LogPath } else{ ScheduledTasks } }
        if ( 'TasksFolder' -in $NewArrayArgs){ if($LogPath -ne $null) { TasksFolder >> $LogPath } else{ TasksFolder } }
        if ( 'HotFixes' -in $NewArrayArgs){ if($LogPath -ne $null) { HotFixes >> $LogPath } else{ HotFixes } }
        if ( 'Antivirus' -in $NewArrayArgs){ if($LogPath -ne $null) { Antivirus >> $LogPath } else{ Antivirus } }
        if ( 'PathCheck' -in $NewArrayArgs){ if($LogPath -ne $null) { PathCheck >> $LogPath } else{ PathCheck } }
        if ( 'FindSpooler' -in $NewArrayArgs){ if($LogPath -ne $null) { FindSpooler >> $LogPath } else{ FindSpooler } }   
    }
}

Write-Output "`t[?] Finish" -ForegroundColor black -BackgroundColor white >> $LogPath
Start-Sleep $Sleep
Read-Host
EXIT
