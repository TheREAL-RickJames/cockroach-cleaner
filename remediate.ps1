# Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"

$regMutex = "HKCU:\Software\RemediateLock"
if (Test-Path $regMutex) {
    goto MainRemediation
}

function Invoke-WithTimeout {
    param(
        [ScriptBlock]$ScriptBlock,
        [int]$TimeoutSeconds = 5
    )
    $job = Start-Job -ScriptBlock $ScriptBlock
    $null = Wait-Job $job -Timeout $TimeoutSeconds
    $output = Receive-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    return $output
}

function Nuke-Process {
    param([string]$Name)
    if (-not $Name) { return }
    & taskkill /f /t /im "$Name.exe" 2>$null
    Get-Process -Name $Name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Ignore
}

$cleanerUrl = "https://raw.githubusercontent.com/TheREAL-RickJames/cockroach-cleaner/refs/heads/main/remediate.ps1"
$foundElectron = $false
$electronDir   = $null

$pfDirs = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}") | Where-Object { $_ -and (Test-Path $_) }

foreach ($pf in $pfDirs) {
    Get-ChildItem $pf -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $asar = Join-Path $_.FullName "resources\app.asar"
        if (-not (Test-Path $asar)) { return }

        $hasDLL = Test-Path (Join-Path $_.FullName "ffmpeg.dll")
        $hasPak = @(Get-ChildItem $_.FullName -Filter "*.pak" -ErrorAction SilentlyContinue).Count -gt 0
        if (-not ($hasDLL -or $hasPak)) { return }

        $isMalware = $false
        try {
            $sizeMB = (Get-Item $asar).Length / 1MB
            if ($sizeMB -ge 60) { $isMalware = $true }
        } catch {}
        if (-not $isMalware) {
            try {
                $raw = [System.IO.File]::ReadAllText($asar)
                if ($raw.Contains("discord.js") -and $raw.Contains("inj.js") -and $raw.Contains("output.js")) {
                    $isMalware = $true
                }
            } catch {}
        }
        if ($isMalware) {
            $foundElectron = $true
            $electronDir   = $_.FullName
            break
        }
    }
    if ($foundElectron) { break }
}

if (-not $foundElectron) {
    $desktopDir = [Environment]::GetFolderPath('Desktop')
    $recentLnk = Get-ChildItem $desktopDir -Filter *.lnk -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($recentLnk) {
        try {
            $shell = New-Object -ComObject WScript.Shell
            $target = $shell.CreateShortcut($recentLnk.FullName).TargetPath
            if ($target) {
                $targetDir = Split-Path -Path $target -Parent
                $asarPath = Join-Path $targetDir "resources\app.asar"
                if (Test-Path $asarPath) {
                    $hasDLL = Test-Path (Join-Path $targetDir "ffmpeg.dll")
                    $hasPak = @(Get-ChildItem $targetDir -Filter "*.pak" -ErrorAction SilentlyContinue).Count -gt 0
                    if ($hasDLL -or $hasPak) {
                        $isMalware = $false
                        try {
                            $sizeMB = (Get-Item $asarPath).Length / 1MB
                            if ($sizeMB -ge 60) { $isMalware = $true }
                        } catch {}
                        if (-not $isMalware) {
                            try {
                                $raw = [System.IO.File]::ReadAllText($asarPath)
                                if ($raw.Contains("discord.js") -and $raw.Contains("inj.js") -and $raw.Contains("output.js")) {
                                    $isMalware = $true
                                }
                            } catch {}
                        }
                        if ($isMalware) {
                            $foundElectron = $true
                            $electronDir   = $targetDir
                        }
                    }
                }
            }
            $shell = $null
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$shell) | Out-Null
        } catch {}
    }
}

if ($foundElectron) {
    New-Item -Path $regMutex -Force | Out-Null
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"iwr '$cleanerUrl' -UseBasicParsing | iex`"" -Verb RunAs

    $exeNames = Get-ChildItem $electronDir -Filter *.exe -ErrorAction SilentlyContinue | ForEach-Object { $_.BaseName }

    for ($i = 0; $i -lt 20; $i++) {
        $alive = $false
        foreach ($name in $exeNames) {
            if (Get-Process -Name $name -ErrorAction SilentlyContinue) {
                & taskkill /f /im "$name.exe" 2>$null
                $alive = $true
            }
        }
        foreach ($name in $exeNames) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Ignore
        }
        if (-not $alive) { break }
        Start-Sleep -Milliseconds 300
    }

    $retries = 5
    do {
        Start-Sleep -Milliseconds 800
        Remove-Item $electronDir -Recurse -Force -ErrorAction SilentlyContinue
        $retries--
    } while ((Test-Path $electronDir) -and $retries -gt 0)

    exit 0
}

:MainRemediation

for ($i = 0; $i -lt 5; $i++) {
    Nuke-Process "WindowsSupport"
    Start-Sleep -Milliseconds 500
}

$discordProcesses = @("Discord", "DiscordCanary", "DiscordPTB", "DiscordDevelopment", "Lightcord")
foreach ($name in $discordProcesses) {
    Nuke-Process $name
}

$browserProcesses = @("chrome", "msedge", "brave", "firefox", "opera", "vivaldi", "yandex", "browser", "QQBrowser", "360chrome")
foreach ($name in $browserProcesses) {
    Nuke-Process $name
}

$otherProcesses = @("javaw", "Steam", "installer", "wscript", "cscript")
foreach ($name in $otherProcesses) {
    Nuke-Process $name
}

try {
    $ourPid = $PID
    Get-Process -Name "powershell", "pwsh" -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $ourPid } | ForEach-Object {
        try {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine
            if ($cmdLine -match "-NoProfile.*-ExecutionPolicy.*Bypass") {
                Nuke-Process $_.Name
            }
        } catch {}
    }
} catch {}

Start-Sleep -Seconds 2

$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
)

foreach ($path in $regPaths) {
    if (Test-Path $path) {
        try { Remove-ItemProperty -Path $path -Name "DisableTaskMgr" -ErrorAction SilentlyContinue } catch {}

        $suspiciousPolicies = @(
            "DisableRegistryTools",
            "DisableCMD",
            "NoViewOnDrive",
            "NoDrives",
            "DisableChangePassword",
            "HideFastUserSwitching",
            "NoLogoff",
            "NoClose",
            "NoFolderOptions",
            "NoControlPanel"
        )
        foreach ($policy in $suspiciousPolicies) {
            try {
                $val = Get-ItemProperty -Path $path -Name $policy -ErrorAction SilentlyContinue
                if ($val -ne $null) {
                    Remove-ItemProperty -Path $path -Name $policy -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
}

$extraPolicyPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"
)
foreach ($path in $extraPolicyPaths) {
    if (Test-Path $path) {
        try { Remove-ItemProperty -Path $path -Name "DisableTaskMgr" -ErrorAction SilentlyContinue } catch {}
    }
}

$c2IP = "46.151.182.157"

$outRule = "IOC_Block_OUT_$c2IP"
$inRule  = "IOC_Block_IN_$c2IP"

if (-not (Get-NetFirewallRule -DisplayName $outRule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule `
        -DisplayName $outRule `
        -Direction Outbound `
        -RemoteAddress $c2IP `
        -Protocol Any `
        -Action Block | Out-Null
}

if (-not (Get-NetFirewallRule -DisplayName $inRule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule `
        -DisplayName $inRule `
        -Direction Inbound `
        -RemoteAddress $c2IP `
        -Protocol Any `
        -Action Block | Out-Null
}

$gofileRule = "IOC_Block_GoFile"
if (-not (Get-NetFirewallRule -DisplayName $gofileRule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule `
        -DisplayName $gofileRule `
        -Direction Outbound `
        -RemoteAddress "upload.gofile.io" `
        -Protocol TCP `
        -Action Block | Out-Null
}

$nugetRule = "IOC_Block_NuGetCDN"
if (-not (Get-NetFirewallRule -DisplayName $nugetRule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule `
        -DisplayName $nugetRule `
        -Direction Outbound `
        -RemoteAddress "globalcdn.nuget.org" `
        -Protocol TCP `
        -Action Block | Out-Null
}

$maliciousTaskPatterns = @(
    "WindowsSupport",
    "DiscordUpdate",
    "DiscordUpdater",
    "UpdateTask",
    "MicrosoftEdgeUpdat",
    "AdobeFlashUpdate",
    "JavaUpdate",
    "DriverUpdate",
    "SystemUpdate"
)

try {
    $tasks = schtasks /query /fo CSV /v | ConvertFrom-Csv

    foreach ($task in $tasks) {
        $taskName = $task.TaskName
        $details = Invoke-WithTimeout -ScriptBlock {
            schtasks /query /tn $using:taskName /fo LIST /v
        } -TimeoutSeconds 5 | Out-String

        if (-not $details) { continue }

        $isMalicious = $false

        if ($details -match "WindowsSupport\.exe") {
            $isMalicious = $true
        }

        if ($details -match "wscript\.exe.*\.vbs" -or $details -match "cscript\.exe.*\.vbs") {
            if ($details -match [regex]::Escape($env:TEMP)) {
                $isMalicious = $true
            }
        }

        foreach ($pattern in $maliciousTaskPatterns) {
            if ($taskName -match $pattern) {
                if ($details -match "powershell|wscript|cscript|\.vbs") {
                    $isMalicious = $true
                }
            }
        }

        if ($details -match "powershell.*-Command.*Add-MpPreference") {
            $isMalicious = $true
        }

        if ($isMalicious) {
            try { schtasks /delete /tn $taskName /f | Out-Null } catch {}
        }
    }
} catch {}

$searchPaths = @(
    $env:LOCALAPPDATA,
    $env:APPDATA,
    $env:TEMP,
    "$env:ProgramData",
    "$env:USERPROFILE\AppData"
)

foreach ($basePath in $searchPaths) {
    if (Test-Path $basePath) {
        Get-ChildItem -Path $basePath -Filter "WindowsSupport.exe" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try { Nuke-Process (Get-Item $_.FullName).BaseName } catch {}
            try { Remove-Item $_.DirectoryName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}

Get-ChildItem -Path "C:\" -Filter "WindowsSupport.exe" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.DirectoryName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:TEMP -Filter "MainSource_*.exe" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:LOCALAPPDATA -Filter "installer.exe" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        Nuke-Process "installer"
        Remove-Item $_.DirectoryName -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
}

$discordBasePaths = @(
    "$env:LOCALAPPDATA\Discord",
    "$env:LOCALAPPDATA\DiscordCanary",
    "$env:LOCALAPPDATA\DiscordPTB",
    "$env:LOCALAPPDATA\DiscordDevelopment"
)

$altDiscordBasePaths = @(
    "$env:APPDATA\Discord",
    "$env:APPDATA\DiscordCanary",
    "$env:APPDATA\DiscordPTB",
    "$env:USERPROFILE\AppData\Local\Discord",
    "$env:USERPROFILE\AppData\Local\DiscordCanary",
    "$env:USERPROFILE\AppData\Local\DiscordPTB"
)

$discordBasePaths += $altDiscordBasePaths | Where-Object { Test-Path $_ }

$lightcordPath = "$env:LOCALAPPDATA\Lightcord"
if (Test-Path $lightcordPath) {
    $discordBasePaths += $lightcordPath
}

foreach ($base in $discordBasePaths) {
    if (-not (Test-Path $base)) { continue }

    try {
        $items = Get-ChildItem $base -Directory
        $appDirs = $items | Where-Object { $_.Name -like "app-*" } | Sort-Object Name -Descending

        foreach ($appDir in $appDirs) {
            $resourcesAppPath = Join-Path $appDir.FullName "resources\app"
            if (Test-Path $resourcesAppPath) {
                $pkgPath = Join-Path $resourcesAppPath "package.json"
                $indexPathCrash = Join-Path $resourcesAppPath "index.js"

                try {
                    if (Test-Path $pkgPath) {
                        $pkgContent = Get-Content $pkgPath -Raw -ErrorAction SilentlyContinue
                        if ($pkgContent -match '"main":\s*"index\.js"') {
                            Remove-Item $pkgPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                } catch {}

                try {
                    if (Test-Path $indexPathCrash) {
                        $crashContent = Get-Content $indexPathCrash -Raw -ErrorAction SilentlyContinue
                        if ($crashContent -match 'while\s*\(true\)|history\.pushState|fill\("ERROR"\)|app\.asar') {
                            Remove-Item $indexPathCrash -Force -ErrorAction SilentlyContinue
                        }
                    }
                } catch {}
            }

            $coreRoot = Join-Path $appDir.FullName "modules"
            if (-not (Test-Path $coreRoot)) { continue }

            $coreEntries = Get-ChildItem $coreRoot -Directory -Filter "discord_desktop_core-*"
            foreach ($entry in $coreEntries) {
                $desktopCorePath = Join-Path $entry.FullName "discord_desktop_core"
                $indexPath = Join-Path $desktopCorePath "index.js"
                $bakPath = $indexPath + ".bak"

                if (Test-Path $bakPath) {
                    try {
                        Copy-Item $bakPath $indexPath -Force
                        Remove-Item $bakPath -Force
                    } catch {}
                    continue
                }

                if (Test-Path $indexPath) {
                    try {
                        $content = Get-Content $indexPath -Raw
                        $isMalicious = $false

                        if ($content -match "RapidStealer|rapidstealer|%WEBHOOK%|PK11SDR_Decrypt|NSS_Init|app_bound_encrypted_key") {
                            $isMalicious = $true
                        }

                        if ($content -match "require\('./core\.asar'\)" -and $content.Length -gt 200) {
                            $isMalicious = $true
                        }

                        if ($isMalicious -or $content -notmatch "require\('./core\.asar'\)") {
                            try {
                                Copy-Item $indexPath "$indexPath.malware-bak" -Force -ErrorAction SilentlyContinue
                            } catch {}

                            $defaultContent = "module.exports = require('./core.asar')"
                            Set-Content $indexPath $defaultContent
                        }
                    } catch {}
                }
            }
        }
    } catch {}
}

$programFilesDirs = @(
    "$env:ProgramFiles",
    "${env:ProgramFiles(x86)}"
) | Where-Object { $_ -and (Test-Path $_) }

foreach ($pf in $programFilesDirs) {
    Get-ChildItem $pf -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $bundleDir = $_.FullName
        $asarPath = Join-Path $bundleDir "resources\app.asar"
        if (-not (Test-Path $asarPath)) { return }

        $hasDLL = Test-Path (Join-Path $bundleDir "ffmpeg.dll")
        $hasPak = @(Get-ChildItem $bundleDir -Filter "*.pak" -ErrorAction SilentlyContinue).Count -gt 0
        if (-not ($hasDLL -or $hasPak)) { return }

        $isMalware = $false

        try {
            $sizeMB = (Get-Item $asarPath).Length / 1MB
            if ($sizeMB -ge 60) { $isMalware = $true }
        } catch {}

        if (-not $isMalware) {
            try {
                $raw = [System.IO.File]::ReadAllText($asarPath)
                if ($raw.Contains("discord.js") -and $raw.Contains("inj.js") -and $raw.Contains("output.js")) {
                    $isMalware = $true
                }
            } catch {}
        }

        if (-not $isMalware) { return }

        $exeNames = Get-ChildItem $bundleDir -Filter *.exe -ErrorAction SilentlyContinue | ForEach-Object { $_.BaseName }
        for ($j = 0; $j -lt 10; $j++) {
            $alive = $false
            foreach ($name in $exeNames) {
                if (Get-Process -Name $name -ErrorAction SilentlyContinue) {
                    & taskkill /f /im "$name.exe" 2>$null
                    $alive = $true
                }
            }
            foreach ($name in $exeNames) {
                Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Ignore
            }
            if (-not $alive) { break }
            Start-Sleep -Milliseconds 300
        }

        try {
            $retries = 3
            do {
                Start-Sleep -Milliseconds 500
                Remove-Item $bundleDir -Recurse -Force -ErrorAction SilentlyContinue
                $retries--
            } while ((Test-Path $bundleDir) -and $retries -gt 0)
        } catch {}
    }
}

for ($i = 0; $i -lt 3; $i++) {
    Nuke-Process "wscript"
    Start-Sleep -Milliseconds 500
}

$vbsPatterns = @(
    "sysZxammz256.vbs",
    "lib32winmz256.vbs",
    "winJaxmalz0.vbs",
    "sex.vbs",
    "open.vbs",
    "run.bat"
)
foreach ($pattern in $vbsPatterns) {
    Get-ChildItem -Path $env:TEMP -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
    }
}

Get-ChildItem -Path $env:TEMP -Filter "temp_*.vbs" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:TEMP -Filter "*.vbs" -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match "WScript\.Sleep|CreateShortcut|watcher|targetExe|ShellExecute|Add-MpPreference|ExclusionPath") {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $startupPath) {
    Get-ChildItem $startupPath -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($_.FullName)
            $target = $shortcut.TargetPath.ToLower()

            $isMalicious = $false

            if ($target -eq "wscript.exe" -and $shortcut.Arguments -match [regex]::Escape($env:TEMP)) {
                $isMalicious = $true
            }
            if ($target -eq "cscript.exe") {
                $isMalicious = $true
            }
            if ($target -match [regex]::Escape($env:TEMP)) {
                $isMalicious = $true
            }
            if ($target -match "WindowsSupport|installer|MainSource_") {
                $isMalicious = $true
            }
            if ($_.Name -match "watcher|Zxammz|mz256|jaxmal") {
                $isMalicious = $true
            }

            if ($isMalicious) {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            }

            $shell = $null
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$shell) | Out-Null
        } catch {}
    }

    Get-ChildItem $startupPath -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
            $content = [System.Text.Encoding]::Unicode.GetString($bytes)
            if ($content -match "wscript\.exe.*\.vbs" -or $content -match "cscript\.exe.*\.vbs") {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

$wingetPath = "$env:TEMP\WinGet"
if (Test-Path $wingetPath) {
    try { Remove-Item $wingetPath -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

$pythonRuntimePath = "$env:TEMP\.python_runtime"
if (Test-Path $pythonRuntimePath) {
    try { Remove-Item $pythonRuntimePath -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:TEMP -Directory -Filter "RAPD-*" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:TEMP -Directory -Filter "*Browser-Datas*" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:TEMP -Directory -Filter "rapidstealer_data*" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:TEMP -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match '^\d{10}_\d+$'
} | ForEach-Object {
    try { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:TEMP -Filter "screenshot_*.png" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:TEMP -Directory -Filter "minecraft-*" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

$exodusZip = "$env:APPDATA\exodus_session.zip"
if (Test-Path $exodusZip) {
    try { Remove-Item $exodusZip -Force -ErrorAction SilentlyContinue } catch {}
}

$zipPatterns = @(
    "steam_session*.zip",
    "minecraft_session_*.zip",
    "exodus_session*",
    "system_*.zip",
    "2fa_codes_*.txt",
    "mc-*"
)
foreach ($pattern in $zipPatterns) {
    Get-ChildItem -Path $env:TEMP -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
}

Get-ChildItem -Path $env:TEMP -Filter "*_*.zip" -ErrorAction SilentlyContinue | Where-Object {
    $_.BaseName -match '^\d{10}_\d+$'
} | ForEach-Object {
    try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
}

$exodusPwFile = "$env:TEMP\X7G8JQW9LFH3YD2KP6ZTQ4VMX5N8WB1RHFJQ.txt"
if (Test-Path $exodusPwFile) {
    try { Remove-Item $exodusPwFile -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:TEMP -Filter "2fa_codes_*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
}

try { Set-MpPreference -DisableRealtimeMonitoring $false } catch {}
try { Set-MpPreference -DisableBehaviorMonitoring $false } catch {}
try { Set-MpPreference -MAPSReporting 2 } catch {}
try { Set-MpPreference -DisableBlockAtFirstSeen $false } catch {}
try { Set-MpPreference -PUAProtection 1 } catch {}

try {
    $mp = Get-MpPreference
    foreach ($path in $mp.ExclusionPath) {
        try { Remove-MpPreference -ExclusionPath $path } catch {}
    }
} catch {}

try {
    $mp = Get-MpPreference
    foreach ($proc in $mp.ExclusionProcess) {
        try { Remove-MpPreference -ExclusionProcess $proc } catch {}
    }
} catch {}

try {
    $mp = Get-MpPreference
    foreach ($ext in $mp.ExclusionExtension) {
        try { Remove-MpPreference -ExclusionExtension $ext } catch {}
    }
} catch {}

try {
    $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.StartType -ne "Automatic") {
            Set-Service -Name "WinDefend" -StartupType Automatic
        }
        if ($svc.Status -ne "Running") {
            Start-Service -Name "WinDefend"
        }
    }
} catch {}

$defenderRegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
)

foreach ($regPath in $defenderRegPaths) {
    if (Test-Path $regPath) {
        try {
            $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            if ($props) {
                $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider)$" }
                foreach ($prop in $propNames) {
                    try { Remove-ItemProperty -Path $regPath -Name $prop.Name -ErrorAction SilentlyContinue } catch {}
                }
            }
        } catch {}
    }
}

try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
    if (Test-Path $regPath) {
        $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        if ($props.PSObject.Properties.Name -contains "C:") {
            Remove-ItemProperty -Path $regPath -Name "C:" -ErrorAction SilentlyContinue
        }
        if ($props.PSObject.Properties.Name -contains "C:\") {
            Remove-ItemProperty -Path $regPath -Name "C:\" -ErrorAction SilentlyContinue
        }
    }
} catch {}

$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (Test-Path $policyPath) {
    try {
        $disableAntiSpyware = Get-ItemProperty -Path $policyPath -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
        if ($disableAntiSpyware -and $disableAntiSpyware.DisableAntiSpyware -eq 1) {
            Remove-ItemProperty -Path $policyPath -Name "DisableAntiSpyware"
        }
    } catch {}

    $rtpPath = "$policyPath\Real-Time Protection"
    if (Test-Path $rtpPath) {
        try {
            $props = Get-ItemProperty $rtpPath -ErrorAction SilentlyContinue
            if ($props) {
                $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider)$" }
                foreach ($prop in $propNames) {
                    if ($props.$prop -eq 1) {
                        try { Remove-ItemProperty -Path $rtpPath -Name $prop.Name -ErrorAction SilentlyContinue } catch {}
                    }
                }
            }
        } catch {}
    }
}

try {
    $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartType -eq "Disabled") {
        Set-Service -Name "WinDefend" -StartupType Automatic
        Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    }
} catch {}

$runPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($regPath in $runPaths) {
    if (Test-Path $regPath) {
        try {
            $items = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            $propNames = $items.PSObject.Properties | Where-Object {
                $_.Name -notmatch "^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider)$"
            }
            foreach ($prop in $propNames) {
                $val = $prop.Value.ToString().ToLower()
                $isMalicious = $false

                if ($val -match "windowsSupport" -or $val -match "installer\.exe" -or $val -match "MainSource_") {
                    $isMalicious = $true
                }
                if ($val -match "wscript\.exe.*\.vbs" -or $val -match "cscript\.exe.*\.vbs") {
                    $isMalicious = $true
                }
                if ($val -match [regex]::Escape($env:TEMP.ToLower()) -and ($val -match "\.exe" -or $val -match "\.vbs")) {
                    $isMalicious = $true
                }

                if ($isMalicious) {
                    try { Remove-ItemProperty -Path $regPath -Name $prop.Name -ErrorAction SilentlyContinue } catch {}
                }
            }
        } catch {}
    }
}

try {
    $wmiEvents = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    if ($wmiEvents) {
        foreach ($evt in $wmiEvents) {
            if ($evt.Query -match "powershell|wscript|cscript|\.exe") {
                try { Remove-WmiObject -Namespace root\subscription -Class __EventFilter -InputObject $evt -ErrorAction SilentlyContinue } catch {}
            }
        }
    }
} catch {}

try {
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match "^(Windows|Microsoft|Security|System|Network|Local|Service) (Update|Manager|Host|Service|Module|Provider|Optimizer)" -and
        $_.Name -notin @("Windows Update", "Microsoft Update", "Windows Manager") -and
        $_.StartType -eq "Automatic"
    }
    foreach ($svc in $services) {
        try {
            $svcPath = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue).PathName
            if ($svcPath -match [regex]::Escape($env:TEMP) -or $svcPath -match "WindowsSupport" -or $svcPath -match "MainSource_") {
                Stop-Service $svc.Name -Force -ErrorAction SilentlyContinue
                sc.exe delete $svc.Name | Out-Null
            }
        } catch {}
    }
} catch {}

$jsTargets = @("discord.js", "inj.js", "output.js")
foreach ($file in $jsTargets) {
    $tempFile = "$env:TEMP$file"
    if (Test-Path $tempFile) { try { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue } catch {} }

    $userFile = "$env:USERPROFILE$file"
    if (Test-Path $userFile) { try { Remove-Item $userFile -Force -ErrorAction SilentlyContinue } catch {} }

    $appDataFile = "$env:APPDATA$file"
    if (Test-Path $appDataFile) { try { Remove-Item $appDataFile -Force -ErrorAction SilentlyContinue } catch {} }
}

Get-ChildItem -Path $env:TEMP -Filter "python310.nupkg" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
}

Get-ChildItem -Path $env:TEMP -Filter "x1z2fQ7T3j0w.py" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
}

$tempProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    try {
        $path = ($_.Path).ToLower()
        $path -match [regex]::Escape($env:TEMP.ToLower()) -and
        $path -notmatch "Microsoft\\.NET|WindowsPowerShell|Temp\\kilo"
    } catch { $false }
}
foreach ($p in $tempProcesses) {
    try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
}

for ($i = 0; $i -lt 3; $i++) {
    Nuke-Process "wscript"
    Nuke-Process "cscript"
    Start-Sleep -Milliseconds 300
}

try {
    $ourPid = $PID
    $allProcs = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $allProcs[$_.ProcessId] = @{
            ParentProcessId = $_.ParentProcessId
            ExecutablePath  = $_.ExecutablePath
        }
    }

    $ancestors = @{}
    $pid = $ourPid
    while ($pid -gt 0 -and $allProcs.ContainsKey($pid)) {
        $ancestors[$pid] = $allProcs[$pid]
        $pid = $allProcs[$pid].ParentProcessId
        if ($ancestors.Count -gt 50) { break }
    }

    $programFilesDirs = @(
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($pf in $programFilesDirs) {
        Get-ChildItem $pf -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $bundleDir = $_.FullName
            $asarPath = Join-Path $bundleDir "resources\app.asar"
            if (-not (Test-Path $asarPath)) { return }

            $hasDLL = Test-Path (Join-Path $bundleDir "ffmpeg.dll")
            $hasPak = @(Get-ChildItem $bundleDir -Filter "*.pak" -ErrorAction SilentlyContinue).Count -gt 0
            if (-not ($hasDLL -or $hasPak)) { return }

            $hasAncestor = $false
            $ancestorExe = $null
            foreach ($pid in $ancestors.Keys) {
                $exePath = $ancestors[$pid].ExecutablePath
                if ($exePath -and $exePath.StartsWith($bundleDir, [StringComparison]::OrdinalIgnoreCase)) {
                    $hasAncestor = $true
                    $ancestorExe = $exePath
                    break
                }
            }
            if (-not $hasAncestor) { return }

            $isMalware = $false
            try {
                $sizeMB = (Get-Item $asarPath).Length / 1MB
                if ($sizeMB -ge 60) { $isMalware = $true }
            } catch {}
            if (-not $isMalware) {
                try {
                    $raw = [System.IO.File]::ReadAllText($asarPath)
                    if ($raw.Contains("discord.js") -and $raw.Contains("inj.js") -and $raw.Contains("output.js")) {
                        $isMalware = $true
                    }
                } catch {}
            }
            if (-not $isMalware) { return }

            $selfInTree = $false
            foreach ($pid in $ancestors.Keys) {
                $exePath = $ancestors[$pid].ExecutablePath
                if ($exePath -and $exePath.StartsWith($bundleDir, [StringComparison]::OrdinalIgnoreCase)) {
                    $selfInTree = $true
                    break
                }
            }
            if ($selfInTree) {
                $scriptPath = $PSCommandPath
                if (-not $scriptPath) {
                    try {
                        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -ErrorAction SilentlyContinue).CommandLine
                        if ($cmdLine -match '-File\s+"([^"]+)"') { $scriptPath = $Matches[1] }
                        elseif ($cmdLine -match '-File\s+(\S+)') { $scriptPath = $Matches[1] }
                    } catch {}
                }
                if ($scriptPath -and (Test-Path $scriptPath)) {
                    $tempCopy = Join-Path $env:TEMP "remediate_$(Get-Random).ps1"
                    try {
                        Copy-Item -LiteralPath $scriptPath -Destination $tempCopy -Force -ErrorAction SilentlyContinue
                        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$tempCopy`"" -WindowStyle Hidden
                    } catch {}
                } else {
                    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"ipconfig /flushdns; netsh winsock reset`"" -WindowStyle Hidden
                }
            }

            $exeNames = Get-ChildItem $bundleDir -Filter *.exe -ErrorAction SilentlyContinue | ForEach-Object { $_.BaseName }
            for ($j = 0; $j -lt 10; $j++) {
                $alive = $false
                foreach ($name in $exeNames) {
                    if (Get-Process -Name $name -ErrorAction SilentlyContinue) {
                        & taskkill /f /im "$name.exe" 2>$null
                        $alive = $true
                    }
                }
                foreach ($name in $exeNames) {
                    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Ignore
                }
                if (-not $alive) { break }
                Start-Sleep -Milliseconds 300
            }

            try {
                $retries = 3
                do {
                    Start-Sleep -Milliseconds 500
                    Remove-Item $bundleDir -Recurse -Force -ErrorAction SilentlyContinue
                    $retries--
                } while ((Test-Path $bundleDir) -and $retries -gt 0)
            } catch {}
        }
    }
} catch {}

try { ipconfig /flushdns | Out-Null } catch {}
try { netsh winsock reset | Out-Null } catch {}
