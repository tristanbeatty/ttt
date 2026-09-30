# ============================
# Requirements & Configuration
# ============================
#Requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Force TLS 1.2/1.3 for web requests
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# ============================
# Run As Administrator
# ============================
function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Restarting as Administrator...' -ForegroundColor Yellow

        $cmdPath =$PSCommandPath
        if (-not $cmdPath -and $MyInvocation.MyCommand -and ($MyInvocation.MyCommand | Get-Member -Name Path -ErrorAction SilentlyContinue)) {
            $cmdPath =$MyInvocation.MyCommand.Path
        }
        if (-not $cmdPath) {$cmdPath = (Get-Location).Path }

        $args = "-NoProfile -ExecutionPolicy Bypass -File `"`"$cmdPath`"`""
        $exe = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
        if (-not $exe) {$exe = (Get-Command powershell.exe -ErrorAction Stop).Source }

        Start-Process -FilePath $exe -ArgumentList$args -Verb RunAs
        exit
    }
}

# ============================
# Initialization & Paths
# ============================
function Initialize {
    $cmdPath =$PSCommandPath
    if (-not $cmdPath -and $MyInvocation.MyCommand -and ($MyInvocation.MyCommand | Get-Member -Name Path -ErrorAction SilentlyContinue)) {
        $cmdPath =$MyInvocation.MyCommand.Path
    }
    if (-not $cmdPath) {$cmdPath = (Get-Location).Path }

    $script:BaseDir    = Split-Path -Parent$cmdPath
    $script:LogsDir    = Join-Path$BaseDir 'Logs'
    $script:ScriptsDir = Join-Path$BaseDir 'Scripts'
    New-Item -ItemType Directory -Force -Path $LogsDir,$ScriptsDir | Out-Null

    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'$script:LogFile = Join-Path $LogsDir "Dashboard_$ts.log"
    try { Start-Transcript -Path $LogFile -Append | Out-Null } catch {}

    try { $Host.UI.RawUI.WindowTitle = "TPuff Tech Tools - $env:COMPUTERNAME" } catch {}
}

# ============================
# UI Helpers
# ============================
function Write-SectionTitle {
    param (
        [string]$Title,
        [ConsoleColor]$Color = 'Cyan'
    )
    $line = ('=' * ($Title.Length + 4))
    Write-Host ""
    Write-Host ('+{0}+' -f $line) -ForegroundColor$Color
    Write-Host ('|  {0}  |' -f $Title) -ForegroundColor$Color
    Write-Host ('+{0}+' -f $line) -ForegroundColor$Color
    Write-Host ""
}

function Show-Header {
    Clear-Host
    Write-SectionTitle "TPuff Tech Tools"
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "Log: $LogFile"
    Write-Host ""
}

function Pause-Return { 
    [void](Read-Host "Press Enter to return to menu") 
}

# ============================
# Script Picker UI
# ============================
function Invoke-ScriptPicker {
    $items = @(Get-ChildItem -Path$ScriptsDir -Filter *.ps1 -File -ErrorAction SilentlyContinue | Sort-Object Name)

    if (-not $items -or$items.Count -eq 0) {
        Write-Host "No .ps1 files in $ScriptsDir" -ForegroundColor Yellow
        Pause-Return
        return
    }

    Clear-Host
    Write-Host "Available Scripts:" -ForegroundColor Cyan
    Write-Host "------------------"

    for ($i = 0; $i -lt $items.Count; $i++) {
        Write-Host ("[{0}] {1}" -f ($i + 1), $items[$i].Name)
    }
    Write-Host '[M] Back to Main Menu'
    Write-Host ""

    $sel = Read-Host "Choose number of script to run"
    if ($sel.Trim().ToUpper() -eq 'M') { return }

    if ($sel -as [int] -and $sel -ge 1 -and$sel -le $items.Count) {$target = $items[$sel - 1].FullName
        try {
            & $target
        } catch {
            Write-Host ("Error running script: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    } else {
        Write-Host 'Invalid selection' -ForegroundColor Yellow
    }

    Pause-Return
}

# ============================
# System Repair Menu
# ============================
function Run-SystemRepairMenu {
    do {
        Clear-Host
        Write-SectionTitle "System Repair Tools"
        Write-Host '[1] Run SFC Scan (System File Checker)'
        Write-Host '[2] Run DISM RestoreHealth'
        Write-Host '[3] Clear Temporary Files'
        Write-Host '[4] Check Event Logs (Critical/Error last 24h)'
        Write-Host '[5] Schedule Chkdsk on Next Reboot'
        Write-Host '[M] Main Menu'
        Write-Host '[Q] Quit'
        Write-Host ""

        $choice = (Read-Host "Select an option").Trim().ToUpper()

        switch ($choice) {
            '1' {
                Write-Host 'Starting System File Checker...' -ForegroundColor Cyan
                sfc /scannow
                Pause-Return
            }
            '2' {
                Write-Host 'Starting DISM RestoreHealth...' -ForegroundColor Cyan
                DISM /Online /Cleanup-Image /RestoreHealth
                Pause-Return
            }
            '3' {
                Write-Host 'Clearing temporary files...' -ForegroundColor Cyan
                $paths = @(
                    "$env:TEMP\*",
                    "$env:WINDIR\Temp\*",
                    "$env:WINDIR\SoftwareDistribution\Download\*"
                )
                foreach ($path in$paths) {
                    Write-Host "Cleaning $path" -ForegroundColor DarkGray
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                }
                Write-Host 'Cleanup complete.' -ForegroundColor Green
                Pause-Return
            }
            '4' {
                Write-Host 'Fetching Critical and Error events from System and Application logs (Last 24h)...' -ForegroundColor Cyan
                $startTime = (Get-Date).AddHours(-24)
                try {
                    Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=$startTime} -ErrorAction Stop |
                        Select-Object TimeCreated, LogName, ProviderName, Id, Message |
                        Format-Table -AutoSize -Wrap
                } catch {
                    Write-Host "No Critical/Error events found or log unreadable." -ForegroundColor Yellow
                }
                Pause-Return
            }
            '5' {
                Write-Host 'Scheduling Chkdsk for system drive...' -ForegroundColor Cyan
                cmd.exe /c "echo Y | chkdsk C: /f /r"
                Write-Host 'Chkdsk scheduled. Please reboot the computer to run.' -ForegroundColor Green
                Pause-Return
            }
            'M' { return }
            'Q' { $script:ExitRequested =$true; return }
            default { Write-Host 'Invalid selection.'; Start-Sleep 1.2 }
        }
    } until ($false)
}

# ============================
# Native Windows Update Menu
# ============================
function Run-WindowsUpdateMenu {
    do {
        Clear-Host
        Write-SectionTitle "Windows Update Tools (Native)"
        Write-Host '[1] Check for Updates'
        Write-Host '[2] Download & Install Available Updates'
        Write-Host '[M] System Tools Menu'
        Write-Host '[Q] Quit'
        Write-Host ""

        $choice = (Read-Host "Select an option").Trim().ToUpper()

        switch ($choice) {
            '1' {
                try {
                    Write-Host "Searching for updates via COM object..." -ForegroundColor Cyan
                    $Session = New-Object -ComObject Microsoft.Update.Session
                    $Searcher =$Session.CreateUpdateSearcher()
                    $Result =$Searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
                    
                    if ($Result.Updates.Count -eq 0) {
                        Write-Host "No updates found." -ForegroundColor Green
                    } else {
                        Write-Host ("Found {0} updates:" -f $Result.Updates.Count) -ForegroundColor Yellow
                        foreach ($Update in$Result.Updates) {
                            Write-Host "- $($Update.Title)"
                        }
                    }
                } catch {
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                }
                Pause-Return
            }
            '2' {
                try {
                    Write-Host "Searching for updates..." -ForegroundColor Cyan
                    $Session = New-Object -ComObject Microsoft.Update.Session
                    $Searcher =$Session.CreateUpdateSearcher()
                    $Result =$Searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
                    
                    if ($Result.Updates.Count -eq 0) {
                        Write-Host "No updates found." -ForegroundColor Green
                    } else {
                        $UpdatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
                        foreach ($Update in$Result.Updates) {
                            if (-not $Update.EulaAccepted) {$Update.AcceptEula() }
                            [void]$UpdatesToDownload.Add($Update)
                        }

                        Write-Host "Downloading $($UpdatesToDownload.Count) updates..." -ForegroundColor Cyan
                        $Downloader =$Session.CreateUpdateDownloader()
                        $Downloader.Updates =$UpdatesToDownload
                        [void]$Downloader.Download()

                        $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                        foreach ($Update in$UpdatesToDownload) {
                            if ($Update.IsDownloaded) { [void]$UpdatesToInstall.Add($Update) }
                        }

                        if ($UpdatesToInstall.Count -gt 0) {
                            Write-Host "Installing $($UpdatesToInstall.Count) updates..." -ForegroundColor Cyan
                            $Installer =$Session.CreateUpdateInstaller()
                            $Installer.Updates =$UpdatesToInstall
                            $InstallResult =$Installer.Install()
                            
                            if ($InstallResult.RebootRequired) {
                                Write-Host "Installation complete. System restart is required." -ForegroundColor Yellow
                            } else {
                                Write-Host "Installation complete. No restart required." -ForegroundColor Green
                            }
                        } else {
                            Write-Host "No updates successfully downloaded to install." -ForegroundColor Yellow
                        }
                    }
                } catch {
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                }
                Pause-Return
            }
            'M' { return }
            'Q' { $script:ExitRequested =$true; return }
            default { Write-Host 'Invalid selection.'; Start-Sleep 1.2 }
        }
    } while ($true)
}

# ============================
# Dell Command Update
# ============================
function Run-DellCommandUpdate {
    Clear-Host
    Write-SectionTitle "Dell Command Update"

    $dcuPaths = @(
        "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
        "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
    )

    $dcuExe =$null
    foreach ($path in$dcuPaths) {
        if (Test-Path $path) { $dcuExe =$path; break }
    }

    if (-not $dcuExe) {
        Write-Host "DCU CLI not found. Attempting install via Winget..." -ForegroundColor Cyan
        try {
            # Execute winget in SYSTEM context explicitly accepting agreements
            $proc = Start-Process -FilePath "winget" -ArgumentList "install -e --id Dell.CommandUpdate --accept-package-agreements --accept-source-agreements --silent" -Wait -PassThru -NoNewWindow
            if ($proc.ExitCode -ne 0) {
                Write-Host "Winget installation failed. Please deploy Dell Command Update via NinjaOne repository." -ForegroundColor Red
                Pause-Return
                return
            }
            
            # Re-verify path after install
            foreach ($path in$dcuPaths) {
                if (Test-Path $path) { $dcuExe =$path; break }
            }
        } catch {
            Write-Host "Winget execution failed. Please deploy Dell Command Update via NinjaOne repository." -ForegroundColor Red
            Pause-Return
            return
        }
    }

    if ($dcuExe) {
        Write-Host "Running: $dcuExe /applyupdates /silent" -ForegroundColor Yellow
        $proc = Start-Process -FilePath$dcuExe -ArgumentList "/applyupdates /silent" -Wait -PassThru -NoNewWindow
        
        if ($proc.ExitCode -eq 0) {             Write-Host "Dell updates applied successfully." -ForegroundColor Green         } elseif ($proc.ExitCode -eq 1) {
            Write-Host "Dell updates applied. A system reboot is required." -ForegroundColor Yellow
        } else {
            Write-Host "Dell Command Update returned code $($proc.ExitCode)." -ForegroundColor Red
        }
    } else {
        Write-Host "DCU CLI still not found after installation attempt." -ForegroundColor Red
    }

    Pause-Return
}

# ============================
# Network Tools Menu
# ============================
function Run-NetworkToolsMenu {
    do {
        Clear-Host
        Write-SectionTitle "Network Tools"
        Write-Host '[1] Show IP configuration'
        Write-Host '[2] Release/Renew DHCP'
        Write-Host '[3] Flush DNS cache'
        Write-Host '[4] Display Routing Table'
        Write-Host '[5] Show Active Connections'
        Write-Host '[M] Main Menu'
        Write-Host '[Q] Quit'
        Write-Host ""

        $netChoice = (Read-Host "Select an option").Trim().ToUpper()
        switch ($netChoice) {
            '1' { ipconfig /all; Pause-Return }
            '2' { ipconfig /release; Start-Sleep 2; ipconfig /renew; Pause-Return }
            '3' { ipconfig /flushdns; Pause-Return }
            '4' { route print; Pause-Return }
            '5' { netstat -ano; Pause-Return }
            'M' { return }
            'Q' { $script:ExitRequested =$true; return }
            default { Write-Host 'Unknown option.'; Start-Sleep 1.2 }
        }
    } until ($false)
}

# ============================
# Printer Tools Menu
# ============================
function Run-PrinterToolsMenu {
    do {
        Clear-Host
        Write-SectionTitle "Printer Tools"
        Write-Host '[1] Open Devices & Printers'
        Write-Host '[2] Restart Spooler'
        Write-Host '[3] Clear Print Queue'
        Write-Host '[4] List Installed Printers'
        Write-Host '[5] List Printer Ports'
        Write-Host '[6] Add Network Printer'
        Write-Host '[M] Main Menu'
        Write-Host '[Q] Quit'
        Write-Host ""

        $netChoice = (Read-Host "Select an option").Trim().ToUpper()
        switch ($netChoice) {
            '1' { Start-Process control.exe printers; Pause-Return }
            '2' {
                try {
                    Restart-Service spooler -Force
                    Write-Host 'Print Spooler restarted.' -ForegroundColor Green
                } catch {
                    Write-Host ("Failed to restart spooler: {0}" -f $_.Exception.Message) -ForegroundColor Red
                }
                Pause-Return
            }
            '3' {
                try {
                    Stop-Service spooler -Force
                    
                    # Wait for service lock to release before deleting files
                    $timeout = 10
                    while ((Get-Service spooler).Status -ne 'Stopped' -and $timeout -gt 0) {
                        Start-Sleep -Seconds 1
                        $timeout--
                    }

                    Remove-Item -Path "$env:SystemRoot\System32\spool\PRINTERS\*.*" -Force -Recurse -ErrorAction SilentlyContinue
                    Start-Service spooler
                    Write-Host 'Print Queue cleared.' -ForegroundColor Green
                } catch {
                    Write-Host ("Failed to clear queue: {0}" -f $_.Exception.Message) -ForegroundColor Red
                }
                Pause-Return
            }
            '4' { Get-Printer | Format-Table Name, DriverName, PortName; Pause-Return }
            '5' { Get-PrinterPort | Format-Table Name, PrinterHostAddress; Pause-Return }
            '6' {
                $path = Read-Host "Enter network printer path (\\Server\Printer)"
                try {
                    Add-Printer -ConnectionName $path
                    Write-Host ("Printer added: {0}" -f $path) -ForegroundColor Green
                } catch {
                    Write-Host ("Error adding printer: {0}" -f $_.Exception.Message) -ForegroundColor Red
                }
                Pause-Return
            }
            'M' { return }
            'Q' { $script:ExitRequested =$true; return }
            default { Write-Host 'Invalid selection'; Start-Sleep 1.2 }
        }
    } until ($false)
}

# ============================
# System Tools Menu
# ============================
function Run-SystemToolsMenu {
    do {
        Clear-Host
        Write-SectionTitle "System Tools"
        Write-Host '[1] Show System Info'
        Write-Host '[2] Change Computer Name'
        Write-Host '[3] List Local Users'
        Write-Host '[4] Remove Local User'
        Write-Host '[5] Create Local User'
        Write-Host '[6] Change User Password'
        Write-Host '[7] Windows Update Tools'
        Write-Host '[8] Dell Command Update'
        Write-Host '[M] Main Menu'
        Write-Host '[Q] Quit'
        Write-Host ""

        $choice = (Read-Host "Select an option").Trim().ToUpper()

        switch ($choice) {
            '1' {
                try {
                    Write-Host "Computer" -ForegroundColor Cyan
                    Get-ComputerInfo | Select-Object CsName,OsName,OsVersion,OsBuildNumber,WindowsProductName,CsManufacturer,CsModel,CsTotalPhysicalMemory | Format-List
                    Write-Host "`nUptime" -ForegroundColor Cyan
                    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                    $uptime = (Get-Date) - $boot
                    "{0}d {1}h {2}m" -f [int]$uptime.Days, $uptime.Hours, $uptime.Minutes | Write-Host
                    Write-Host "`nDisks" -ForegroundColor Cyan
                    Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,@{n='Free(GB)';e={[math]::Round($_.SizeRemaining/1GB,1)}},@{n='Size(GB)';e={[math]::Round($_.Size/1GB,1)}} | Sort-Object DriveLetter | Format-Table -Auto
                } catch {
                    Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red
                }
                Pause-Return
            }
            '2' {
                $newName = (Read-Host "Enter new computer name").Trim()
                if ([string]::IsNullOrWhiteSpace($newName)) { Write-Host 'No name entered.'; Pause-Return; return }
                try {
                    Rename-Computer -NewName $newName -Force
                    Write-Host ("Computer name set to {0}" -f $newName) -ForegroundColor Green$r = (Read-Host "Restart now to apply? (Y/N)").Trim().ToUpper()
                    if ($r -eq 'Y') { Restart-Computer -Force }
                } catch { Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
                Pause-Return
            }
            '3' {
                try {
                    Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,PasswordNeverExpires | Sort-Object Name | Format-Table -Auto
                } catch { Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
                Pause-Return
            }
            '4' {
                $user = (Read-Host "Enter local username to remove").Trim()
                if ([string]::IsNullOrWhiteSpace($user)) { Write-Host 'No username entered.'; Pause-Return; return }
                try {
                    $lu = Get-LocalUser -Name$user -ErrorAction SilentlyContinue
                    if (-not $lu) { Write-Host ("User '{0}' not found." -f $user) -ForegroundColor Yellow }
                    elseif ($lu.Name -in @('Administrator','Guest')) { Write-Host "Refusing to remove built-in accounts." -ForegroundColor Yellow }
                    elseif ($lu.Name -eq$env:USERNAME) { Write-Host "Refusing to remove logged-in user." -ForegroundColor Yellow }
                    else {
                        $conf = Read-Host "Type DELETE to confirm removing '$user'"
                        if ($conf -ceq 'DELETE') {
                            Remove-LocalUser -Name $user
                            Write-Host ("User '{0}' removed." -f $user) -ForegroundColor Green
                        } else { Write-Host 'Cancelled.' -ForegroundColor Yellow }
                    }
                } catch { Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
                Pause-Return
            }
            '5' {
                $name = (Read-Host "Enter new username").Trim()
                if ([string]::IsNullOrWhiteSpace($name)) { Write-Host 'No username entered.'; Pause-Return; return }
                try {
                    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { Write-Host ("User '{0}' exists." -f $name) -ForegroundColor Yellow; Pause-Return; return }$full = Read-Host "Full name (optional)"
                    $desc = Read-Host "Description (optional)"
                    Write-Host "Enter initial password:" -ForegroundColor Cyan
                    $pwd = Read-Host -AsSecureString
                    New-LocalUser -Name $name -Password$pwd -FullName $full -Description$desc -ErrorAction Stop
                    Enable-LocalUser -Name $name$grp = (Read-Host "(A)dd to Administrators, (U)sers, or (N)o group change [A/U/N]").Trim().ToUpper()
                    if ($grp -eq 'A') { Add-LocalGroupMember -Group 'Administrators' -Member$name; Write-Host "Added to Administrators." -ForegroundColor Green }
                    elseif ($grp -eq 'U') { Add-LocalGroupMember -Group 'Users' -Member$name; Write-Host "Added to Users." -ForegroundColor Green }
                    Write-Host ("User '{0}' created." -f $name) -ForegroundColor Green
                } catch { Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
                Pause-Return
            }
            '6' {
                $user = (Read-Host "Enter local username to change password").Trim()
                if ([string]::IsNullOrWhiteSpace($user)) { Write-Host 'No username entered.'; Pause-Return; return }
                try {
                    if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) { Write-Host ("User '{0}' not found." -f $user) -ForegroundColor Yellow }
                    else {
                        Write-Host "Enter new password for '$user':" -ForegroundColor Cyan
                        $pwd = Read-Host -AsSecureString$conf = Read-Host "Type PASSWORD to confirm"
                        if ($conf -ceq 'PASSWORD') {
                            Set-LocalUser -Name $user -Password$pwd -ErrorAction Stop
                            Write-Host ("Password updated." -f $user) -ForegroundColor Green
                        } else { Write-Host 'Cancelled.' -ForegroundColor Yellow }
                    }
                } catch { Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
                Pause-Return
            }
            '7' { Run-WindowsUpdateMenu }
            '8' { Run-DellCommandUpdate }
            'M' { return }
            'Q' { $script:ExitRequested =$true; return }
            default { Write-Host 'Unknown option.'; Start-Sleep 1.2 }
        }
    } until ($false)
}

# ============================
# Build Main Menu Items
# ============================
function Build-Menu {
    @(
        @{ Key='1'; Name='System Repair Tools';         Action = { Run-SystemRepairMenu } }
        @{ Key='2'; Name='Network Tools';               Action = { Run-NetworkToolsMenu } }
        @{ Key='3'; Name='Printer Tools';               Action = { Run-PrinterToolsMenu } }
        @{ Key='4'; Name='System Tools';                Action = { Run-SystemToolsMenu } }
        @{ Key='S'; Name='Run a script from .\Scripts'; Action = { Invoke-ScriptPicker } }
        @{ Key='Q'; Name='Quit';                        Action = { $script:ExitRequested =$true } }
    )
}

# ============================
# Main Loop
# ============================
function Run-Menu {
    do {
        Show-Header
        foreach ($item in$script:Menu) {
            Write-Host ("[{0}] {1}" -f $item.Key, $item.Name)
        }
        Write-Host ""
        $choice = (Read-Host "Select option").Trim().ToUpper()
        $match =$script:Menu | Where-Object { $_.Key -eq$choice }
        if ($null -ne$match) {
            try { & $match.Action }
            catch { Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red; Pause-Return }
        } else {
            if ($choice -ne '') { Write-Host 'Unknown option.'; Start-Sleep 1.2 }         }     } until ($script:ExitRequested)
}

# ============================
# Entry Point
# ============================
Ensure-Admin
Initialize
$script:ExitRequested = $false$script:Menu = Build-Menu
Run-Menu
try { Stop-Transcript | Out-Null } catch {}
