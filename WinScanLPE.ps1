# Аргументы командной строки
$arrayargs = [System.Collections.ArrayList]::new()
if($args.Count -gt 0)
{
    for($count = 0; $args.Count -gt $count; $count++)
    {
        [void]$arrayargs.Add( $args[$count] )
    }
}


# =====================================================================================================================
# Проверка привелегий
function CheckPrivileges
{
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) 
}

if (((CheckPrivileges) -eq $false) -or ($Privileges -eq $null))
{
    $Privileges = "User"
}
else
{
    $Privileges = "Administrator"
}

if("Administrator" -in $arrayargs)
{
    $Privileges = "Administrator"
#    $arrayargs.Remove("Administrator")
}

#if($Privileges -eq "Administrator")
#{
#    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ( $myinvocation.MyCommand.Definition ))
#}

# Повышение привелегий скрипта
#if($Privileges -eq "Administrator")
#{
#
#}


# Проверка количества аргументов
#if($args.Count -eq 0)
#{
#    $HotFixes = "False"
#    $Privileges = "User"
#
#    Write-Host "The program runs without arguments"
#
#    Write-Host "Possible modes of operation of the program:"
#    Write-Host "`t all, HotFixes"
#    Write-Host "Default value: all `n"
#    $Mode = $( Read-Host "Input mode, please" )
#    $PrivilegesInput = $( Read-Host "`nEnter 'Administrator' if you want to run the program as administrator" )
#
#
#    if(($Mode -eq "all") -or ( $Mode -eq "HotFixes" ))
#    {
#        $HotFixes = "Start"
#    }
#
#    if($PrivilegesInput -eq "Administrator")
#    {
#        $Privileges = $PrivilegesInput
#    }
#}
# =====================================================================================================================

$Sleep = 0

# =====================================================================================================================
# Проверка наличия аргумента `all`
if("all" -in $arrayargs)
{
    Write-Host "The program is running in full test mode, all tests will be performed"

    $HotFixes = "Start"
    $RunAtStartup = "Start"
    $Date = "Start"
    $AuditSettings = "Start"
    $WEFSettings = "Start"
    $LCPM = "Start"
    $AIE = "Start"
    $NetworkShares = "Start"
    $NetworkInterfaces = "Start"
    $NetworkUsedPorts = "Start"
    $NetworkFirewall = "Start"
    $NetworkRoutes = "Start"
    $LAPS = "Start" 
    $CachedCreds = "Start"
    $AVSettings = "Start"
    $ARP = "Start"
}

# Проверка наличия аргумента `Network`
if("Network" -in $arrayargs)
{
    Write-Host "The program is running in Network test mode, Network tests will be performed"

    $NetworkShares = "Start"
    $NetworkInterfaces = "Start"
    $NetworkUsedPorts = "Start"
    $NetworkFirewall = "Start"
    $NetworkRoutes = "Start"
    $ARP = "Start"
}

# Проверка наличия аргумента `HotFixes`
if("HotFixes" -in $arrayargs)
{
    $HotFixes = "Start"
}

# Проверка наличия аргумента `RunAtStartup`
if("RunAtStartup" -in $arrayargs)
{
    $RunAtStartup = "Start"
}

# Проверка наличия аргумента `Date`
if("Date" -in $arrayargs)
{
    $Date = "Start"
}

# Проверка наличия аргумента `AuditSettings`
if("AuditSettings" -in $arrayargs)
{
    $AuditSettings = "Start"
}

# Проверка наличия аргумента `AuditSettings`
if("WEFSettings" -in $arrayargs)
{
    $WEFSettings = "Start"
}

# Проверка наличия аргумента `LCPM`
if("LCPM" -in $arrayargs)
{
    $LCPM = "Start"
}

# Проверка наличия аргумента `AIE`
if("AIE" -in $arrayargs)
{
    $AIE = "Start"
}

# Проверка наличия аргумента `NetworkShares`
if("NetworkShares" -in $arrayargs)
{
    $NetworkShares = "Start"
}

# Проверка наличия аргумента `NetworkInterfaces`
if("NetworkInterfaces" -in $arrayargs)
{
    $NetworkInterfaces = "Start"
}

# Проверка наличия аргумента `NetworkUsedPorts`
if("NetworkUsedPorts" -in $arrayargs)
{
    $NetworkUsedPorts = "Start"
}

# Проверка наличия аргумента `NetworkFirewall`
if("NetworkFirewall" -in $arrayargs)
{
    $NetworkFirewall = "Start"
}

# Проверка наличия аргумента `NetworkRoutes`
if("NetworkRoutes" -in $arrayargs)
{
    $NetworkRoutes = "Start"
}

# Проверка наличия аргумента `LAPS`
if("LAPS" -in $arrayargs)
{
    $LAPS = "Start"
}

# Проверка наличия аргумента `CachedCreds`
if("CachedCreds" -in $arrayargs)
{
    $CachedCreds = "Start"
}

# Проверка наличия аргумента `AVSettings`
if("AVSettings" -in $arrayargs)
{
    $AVSettings = "Start"
}

# Проверка наличия аргумента `ARP`
if("ARP" -in $arrayargs)
{
    $ARP = "Start"
}

# Проверка наличия аргумента `Sleep` или `Timer`
if(("Sleep" -in $arrayargs) -or ("Timer" -in $arrayargs))
{
    Write-Host "Sleep ="
    $Sleep=read-host
}

# =====================================================================================================================




#  Проверка `HotFixes`
if($HotFixes -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "HotFixes test Started"

    start-sleep -milliseconds $Sleep
    $HotFixes = wmic qfe get Caption,Description,HotFixID,InstalledOn
    start-sleep -milliseconds $Sleep

    if ( systeminfo | findstr /i "2000 XP 2003 2008 vista" ) { Write-Host "Vulns: Old OS version" }
    start-sleep -milliseconds $Sleep

    if ( $HotFixes | findstr /C:"KB2592799" ) { Write-Host "Vulns: XP/SP3,2K3/SP3-afd.sys" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB3143141" ) { Write-Host "Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB2393802" ) { Write-Host "Vulns: XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB982799"  ) { Write-Host "Vulns: 2K8,Vista,7/SP0-Chimichurri" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB979683"  ) { Write-Host "Vulns: 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB2305420" ) { Write-Host "Vulns: 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB981957"  ) { Write-Host "Vulns: XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB4013081" ) { Write-Host "Vulns: 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB977165"  ) { Write-Host "Vulns: 2K,XP,2K3,2K8,Vista,7-User Mode to Ring" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB941693"  ) { Write-Host "Vulns: 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB920958"  ) { Write-Host "Vulns: 2K/SP4-ZwQuerySysInfo" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB914389"  ) { Write-Host "Vulns: 2K,XP/SP2-Mrxsmb.sys" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB908523"  ) { Write-Host "Vulns: 2K/SP4-APC Data-Free" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB890859"  ) { Write-Host "Vulns: 2K/SP3/4,XP/SP1/2-CSRSS" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB842526"  ) { Write-Host "Vulns: 2K/SP2/3/4-Utility Manager" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB835732"  ) { Write-Host "Vulns: 2K/SP2/3/4,XP/SP0/1-LSASS service BoF" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB841872"  ) { Write-Host "Vulns: 2K/SP4-POSIX" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB2975684" ) { Write-Host "Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB3136041" ) { Write-Host "Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB3057191" ) { Write-Host "Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB2989935" ) { Write-Host "Vulns: 2K3/SP2-TCP/IP" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB2778930" ) { Write-Host "Vulns: Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB2850851" ) { Write-Host "Vulns: 7SP0/SP1_x86-schlamperei" }
    start-sleep -milliseconds $Sleep
    if ( $HotFixes | findstr /C:"KB2870008" ) { Write-Host "Vulns: 7SP0/SP1_x86-track_popup_menu" }

    Write-Host "HotFixes test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Заготовка под проверку `RunAtStartup` 
if($RunAtStartup -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "RunAtStartup test Started"
    start-sleep -milliseconds $Sleep
    
    Get-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
    start-sleep -milliseconds $Sleep
    Get-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce 
    start-sleep -milliseconds $Sleep
    Get-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run 
    start-sleep -milliseconds $Sleep
    Get-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
    start-sleep -milliseconds $Sleep
    
    icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"    | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%"
    start-sleep -milliseconds $Sleep
    icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup\*"  | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%"
    start-sleep -milliseconds $Sleep
    icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"   | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%"
    start-sleep -milliseconds $Sleep
    icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup\*" | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%"
    start-sleep -milliseconds $Sleep

    icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup"   | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" 
    start-sleep -milliseconds $Sleep
    icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup\*" | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" 
    start-sleep -milliseconds $Sleep
    icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup"       | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" 
    start-sleep -milliseconds $Sleep
    icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*"     | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" 

    Write-Host "RunAtStartup test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверка даты и времени системы
if($Date -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "System date and time:"
    start-sleep -milliseconds $Sleep
    
    Get-Date

    Write-Host "======================================================================="
    Write-Host
}

# Проверка AuditSettings
if($AuditSettings -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "AuditSettings test Started"
    start-sleep -milliseconds $Sleep
    
    Get-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
    
    Write-Host "AuditSettings test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверка WEFSettings
if($WEFSettings -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "WEFSettings test Started"
    start-sleep -milliseconds $Sleep

    Get-Item -Path HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
    
    Write-Host "WEFSettings test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем LogonCredentialsPlainInMemory `LCPM`
if($LCPM -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "LogonCredentialsPlainInMemory test Started"
    start-sleep -milliseconds $Sleep
    
    Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
    
    Write-Host "LogonCredentialsPlainInMemory test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем AlwaysInstallElevated `AIE`
if($AIE -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "AlwaysInstallElevated test Started"
    start-sleep -milliseconds $Sleep
    
    Get-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer # /v AlwaysInstallElevated
    start-sleep -milliseconds $Sleep
    Get-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer # /v AlwaysInstallElevated
    
    Write-Host "AlwaysInstallElevated test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем NetworkShares
if($NetworkShares -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "NetworkShares test Started"
    start-sleep -milliseconds $Sleep
    
    net share
    
    Write-Host "NetworkShares test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем NetworkInterfaces
if($NetworkInterfaces -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "NetworkInterfaces test Started"
    start-sleep -milliseconds $Sleep
    
    ipconfig  /all
    
    Write-Host "NetworkInterfaces test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем NetworkUsedPorts
if($NetworkUsedPorts -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "NetworkUsedPorts test Started"
    start-sleep -milliseconds $Sleep
    
    netstat -ano | findstr /i listen
    
    Write-Host "NetworkUsedPorts test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем NetworkFirewall
if($NetworkFirewall -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "NetworkFirewall test Started"
    start-sleep -milliseconds $Sleep
    
    netsh firewall show state
    start-sleep -milliseconds $Sleep
    netsh firewall show config
    
    Write-Host "NetworkFirewall test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем NetworkRoutes
if($NetworkRoutes -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "NetworkRoutes test Started"
    start-sleep -milliseconds $Sleep
    
    route print
    
    Write-Host "NetworkRoutes test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем ARP
if($ARP -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "ARP test Started"
    start-sleep -milliseconds $Sleep
    
    arp -A
    
    Write-Host "ARP test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем MountedDisks
if($MountedDisks -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "MountedDisks test Started"
    start-sleep -milliseconds $Sleep
    
    wmic logicaldisk get caption | more 
    start-sleep -milliseconds $Sleep
    fsutil fsinfo drives
    
    Write-Host "MountedDisks test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем LAPS
if($LAPS -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "LAPS test Started"
    start-sleep -milliseconds $Sleep
    
    Get-Item -Path HKLM:\Software\Policies\Microsoft Services\AdmPwd
    start-sleep -milliseconds $Sleep
    Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA # /v RunAsPPL
    start-sleep -milliseconds $Sleep
    Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA # /v LsaCfgFlags
    
    Write-Host "LAPS test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем CachedCreds
if($CachedCreds -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "CachedCreds test Started"
    start-sleep -milliseconds $Sleep
    
    Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon # /v CACHEDLOGONSCOUNT
    
    Write-Host "CachedCreds test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем UACSettings
if($UACSettings -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "UACSettings test Started"
    start-sleep -milliseconds $Sleep
    
    Get-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\ # /v EnableLUA 
    
    Write-Host "UACSettings test passed"
    Write-Host "======================================================================="
    Write-Host
}

# Проверяем AVSettings
if($AVSettings -eq "Start")
{
    Write-Host "======================================================================="
    Write-Host "AVSettings test Started"
    start-sleep -milliseconds $Sleep
    
    Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
    
    Write-Host "AVSettings test passed"
    Write-Host "======================================================================="
    Write-Host
}

Read-Host "Press any button to exit"
