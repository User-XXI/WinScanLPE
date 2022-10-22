# Аргументы командной строки
$arrayargs = [System.Collections.ArrayList]::new()
if($args.Count -gt 0)
{
    for($count = 0; $args.Count -gt $count; $count++)
    {
        [void]$arrayargs.Add( $args[$count] )
    }
}


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


# Проверка наличия аргумента `all`
if("all" -in $arrayargs)
{
    Write-Host "The program is running in full test mode, all tests will be performed"
    $HotFix = "Start"
    $Registry = "Start"
}

# Проверка наличия аргумента `HotFix`
if("HotFix" -in $arrayargs)
{
    $HotFix = "Start"
}

# Проверка наличия аргумента `Registry`
if("Registry" -in $arrayargs)
{
    $Registry = "Start"
}


# Повышение привелегий скрипта
#if($Privileges -eq "Administrator")
#{
#
#}


# Проверка количества аргументов
#if($args.Count -eq 0)
#{
#    $HotFix = "False"
#    $Privileges = "User"
#
#    Write-Host "The program runs without arguments"
#
#    Write-Host "Possible modes of operation of the program:"
#    Write-Host "`t all, HotFix"
#    Write-Host "Default value: all `n"
#    $Mode = $( Read-Host "Input mode, please" )
#    $PrivilegesInput = $( Read-Host "`nEnter 'Administrator' if you want to run the program as administrator" )
#
#
#    if(($Mode -eq "all") -or ( $Mode -eq "HotFix" ))
#    {
#        $HotFix = "Start"
#    }
#
#    if($PrivilegesInput -eq "Administrator")
#    {
#        $Privileges = $PrivilegesInput
#    }
#}



if($HotFix -eq "Start")
{
    Write-Host "HotFix test Started"

    $HotFix = wmic qfe get Caption,Description,HotFixID,InstalledOn

    if ( systeminfo | findstr /i "2000 XP 2003 2008 vista" ) { Write-Host "Vulns: Old OS version" }

    if ( $HotFix | findstr /C:"KB2592799" ) { Write-Host "Vulns: XP/SP3,2K3/SP3-afd.sys" }
    if ( $HotFix | findstr /C:"KB3143141" ) { Write-Host "Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon" }
    if ( $HotFix | findstr /C:"KB2393802" ) { Write-Host "Vulns: XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa" }
    if ( $HotFix | findstr /C:"KB982799"  ) { Write-Host "Vulns: 2K8,Vista,7/SP0-Chimichurri" }
    if ( $HotFix | findstr /C:"KB979683"  ) { Write-Host "Vulns: 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel" }
    if ( $HotFix | findstr /C:"KB2305420" ) { Write-Host "Vulns: 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched" }
    if ( $HotFix | findstr /C:"KB981957"  ) { Write-Host "Vulns: XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout" }
    if ( $HotFix | findstr /C:"KB4013081" ) { Write-Host "Vulns: 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading" }
    if ( $HotFix | findstr /C:"KB977165"  ) { Write-Host "Vulns: 2K,XP,2K3,2K8,Vista,7-User Mode to Ring" }
    if ( $HotFix | findstr /C:"KB941693"  ) { Write-Host "Vulns: 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys" }
    if ( $HotFix | findstr /C:"KB920958"  ) { Write-Host "Vulns: 2K/SP4-ZwQuerySysInfo" }
    if ( $HotFix | findstr /C:"KB914389"  ) { Write-Host "Vulns: 2K,XP/SP2-Mrxsmb.sys" }
    if ( $HotFix | findstr /C:"KB908523"  ) { Write-Host "Vulns: 2K/SP4-APC Data-Free" }
    if ( $HotFix | findstr /C:"KB890859"  ) { Write-Host "Vulns: 2K/SP3/4,XP/SP1/2-CSRSS" }
    if ( $HotFix | findstr /C:"KB842526"  ) { Write-Host "Vulns: 2K/SP2/3/4-Utility Manager" }
    if ( $HotFix | findstr /C:"KB835732"  ) { Write-Host "Vulns: 2K/SP2/3/4,XP/SP0/1-LSASS service BoF" }
    if ( $HotFix | findstr /C:"KB841872"  ) { Write-Host "Vulns: 2K/SP4-POSIX" }
    if ( $HotFix | findstr /C:"KB2975684" ) { Write-Host "Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer" }
    if ( $HotFix | findstr /C:"KB3136041" ) { Write-Host "Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address" }
    if ( $HotFix | findstr /C:"KB3057191" ) { Write-Host "Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys" }
    if ( $HotFix | findstr /C:"KB2989935" ) { Write-Host "Vulns: 2K3/SP2-TCP/IP" }
    if ( $HotFix | findstr /C:"KB2778930" ) { Write-Host "Vulns: Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast" }
    if ( $HotFix | findstr /C:"KB2850851" ) { Write-Host "Vulns: 7SP0/SP1_x86-schlamperei" }
    if ( $HotFix | findstr /C:"KB2870008" ) { Write-Host "Vulns: 7SP0/SP1_x86-track_popup_menu" }

    Write-Host "HotFix test passed"
    Write-Host
}

# Заготовка под проверку реестра
if($Registry -eq "Start")
{
    Write-Host "Registry test Started"

    Get-Item -Path HKLM:\Software\OpenSSH\Agent\Keys

    Write-Host "Registry test passed"
    Write-Host
}

Read-Host "Press any button to exit"
