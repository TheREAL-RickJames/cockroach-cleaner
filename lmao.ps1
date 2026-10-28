<#
  Dev7 Gang ransomware removal tool (beta)

  Finds and removes a Dev7 Gang ransomware infection and undoes what its remote-control
  commands change. Known builds: services-6xJwYxym.jar.
  It recognises the malware by what its program contains and by how it starts,
  not by file, folder or task names, so renamed and moved builds of the same
  kit are found too.

  Usage (from an elevated PowerShell, or double-click Remove-Dev7Gang.cmd):
    .\Remove-Dev7Gang.ps1            check only: lists what it finds, changes nothing
    .\Remove-Dev7Gang.ps1 -Apply     remove what it found
  Options: -CurrentUserOnly (only this user's profile), -Pause (wait for Enter at the end)
  Exit code: 0 nothing to do, 2 something found / reset, 3 something could not be removed or reset.
  Policies, Microsoft Defender and Windows Recovery are always reset to Windows defaults.

  Generated 2026-10-23 by rho9-lab from lab detonations. Signature (data below) v20261023.
#>
[CmdletBinding()]
param([switch]$Apply, [switch]$CurrentUserOnly, [switch]$Pause)

$SignatureJson = @'
{
 "family": "Dev7 Gang ransomware",
 "version": "20261023",
 "dirs": [
  {
   "role": "bot",
   "what": "the remote-control bot (Java)",
   "anchors": [
    "services.jar",
    "java\\bin\\javaw.exe"
   ],
   "parent": "{local}",
   "name": "*"
  }
 ],
 "siblings": [],
 "process_cmdline": "(?i)\\\\AppData\\\\Local\\\\[^\\\\\\\"]+\\\\(services\\.jar)\\b",
 "process_roles": [
  "bot"
 ],
 "task_action": "(?i)\\\\AppData\\\\Local\\\\[^\\\\\\\"]+\\\\(services\\.jar)\\b",
 "uninstall_roles": [
  "app",
  "bot"
 ],
 "shortcut_places": [
  "{home}\\Desktop",
  "{roaming}\\Microsoft\\Windows\\Start Menu\\Programs"
 ],
 "shortcut_roles": [
  "app",
  "bot"
 ],
 "temp": {
  "gate": [
   "ayan_run.lock"
  ],
  "gate_globs": [
   "*_run.lock"
  ],
  "globs": [
   "*_run.lock",
   "ayan_run.lock",
   "jna-*",
   "sqlite-unknown-*-sqlitejdbc.dll",
   "sqlite-unknown-*-sqlitejdbc.dll.lck",
   "ssc*.jpg"
  ]
 },
 "fingerprint": {
  "libs_all": [
   "com/neovisionaries/ws/client/"
  ],
  "libs_any": [
   "org/sqlite/",
   "com/sun/jna/"
  ],
  "obf_class_rx": "^(?:[Iil1]{6,}/)+[A-Za-z0-9$_]+\\.class$",
  "obf_main_rx": "(?m)^Main-Class:\\s*(?:[Iil1]{6,}\\.)+[Iil1]{6,}\\s*$",
  "obf_min_classes": 20,
  "min_size": 1000000,
  "max_size": 400000000
 },
 "effects": [
  {
   "kind": "regvalue",
   "hive": "HKLM",
   "key": "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Users\\jaden\\AppData",
   "name": "Local",
   "data": "0",
   "what": "setting changed by !cookie"
  },
  {
   "kind": "policy",
   "hive": "HKCU",
   "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
   "name": "DisableTaskMgr",
   "default": null,
   "what": "Task Manager disabled"
  },
  {
   "kind": "policy",
   "hive": "HKLM",
   "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
   "name": "DisableTaskMgr",
   "default": null,
   "what": "Task Manager disabled"
  },
  {
   "kind": "policy",
   "hive": "HKCU",
   "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
   "name": "DisableRegistryTools",
   "default": null,
   "what": "Registry Editor disabled"
  },
  {
   "kind": "policy",
   "hive": "HKLM",
   "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
   "name": "DisableRegistryTools",
   "default": null,
   "what": "Registry Editor disabled"
  },
  {
   "kind": "policy",
   "hive": "HKCU",
   "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
   "name": "DisableLockWorkstation",
   "default": null,
   "what": "Lock screen disabled"
  },
  {
   "kind": "policy",
   "hive": "HKCU",
   "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
   "name": "DisableChangePassword",
   "default": null,
   "what": "Change password disabled"
  },
  {
   "kind": "policy",
   "hive": "HKCU",
   "key": "Software\\Policies\\Microsoft\\Windows\\System",
   "name": "DisableCMD",
   "default": null,
   "what": "Command Prompt disabled"
  },
  {
   "kind": "policy",
   "hive": "HKCU",
   "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
   "name": "NoRun",
   "default": null,
   "what": "Run dialog disabled"
  },
  {
   "kind": "policy",
   "hive": "HKCU",
   "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
   "name": "NoControlPanel",
   "default": null,
   "what": "Control Panel / Settings disabled"
  },
  {
   "kind": "policy",
   "hive": "HKCU",
   "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
   "name": "NoFolderOptions",
   "default": null,
   "what": "Folder Options disabled"
  },
  {
   "kind": "policy",
   "hive": "HKCU",
   "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
   "name": "SettingsPageVisibility",
   "default": null,
   "what": "Settings pages hidden (the gang hides Recovery with !s\u0131f\u0131rlama)"
  },
  {
   "kind": "policy",
   "hive": "HKLM",
   "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
   "name": "SettingsPageVisibility",
   "default": null,
   "what": "Settings pages hidden"
  },
  {
   "kind": "policy",
   "hive": "HKLM",
   "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
   "name": "EnableLUA",
   "default": 1,
   "what": "User Account Control off"
  },
  {
   "kind": "policy",
   "hive": "HKLM",
   "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
   "name": "ConsentPromptBehaviorAdmin",
   "default": 5,
   "what": "UAC prompts for administrators turned off"
  },
  {
   "kind": "policy",
   "hive": "HKLM",
   "key": "SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore",
   "name": "DisableSR",
   "default": null,
   "what": "System Restore disabled"
  },
  {
   "kind": "policy",
   "hive": "HKLM",
   "key": "SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore",
   "name": "DisableConfig",
   "default": null,
   "what": "System Restore settings locked"
  },
  {
   "kind": "policy_key",
   "key": "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
   "what": "Microsoft Defender policies"
  },
  {
   "kind": "policy_key_if_empty",
   "hive": "HKCU",
   "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
   "what": "empty policy key left by the gang's Task Manager lock (!task)"
  },
  {
   "kind": "policy_key_if_empty",
   "hive": "HKCU",
   "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
   "what": "empty policy key left by the gang's Recovery lock (!s\u0131f\u0131rlama)"
  },
  {
   "kind": "defender",
   "what": "Microsoft Defender settings"
  },
  {
   "kind": "winre",
   "what": "Windows Recovery switched off (blocks Reset this PC; the gang can do this remotely)"
  },
  {
   "kind": "file_restore",
   "what": "Discord modified to send the login token (!inject)",
   "glob": "{local}\\Discord*\\app-*\\modules\\discord_desktop_core-*\\discord_desktop_core\\index.js",
   "clean": "module.exports = require('./core.asar');"
  },
  {
   "kind": "report_files",
   "what": "files encrypted by the malware",
   "glob": "*.cryptedmicro",
   "advice": "- don't delete them; they can be decrypted (ask whoever gave you this tool)"
  },
  {
   "kind": "dropped_exe",
   "what": "program downloaded onto the PC by the operators (!cookie)",
   "places": [
    "{local}",
    "{roaming}",
    "{home}\\AppData\\LocalLow",
    "{local}\\Temp"
   ],
   "masquerade_rx": "^(svchost|csrss|lsass|winlogon|services|smss|dllhost|conhost|explorer|taskhostw|runtimebroker|wininit|spoolsv|ctfmon|sihost|taskmgr|system|lsm|audiodg|fontdrvhost|searchindexer|winupdate|windowsupdate)[0-9_-]*$"
  }
 ],
 "builds": [
  {
   "name": "services-6xJwYxym.jar",
   "sha256": "a8ef62530889b996f949ab460bea1810621ac4d46050af63eb360984df4eb3ff",
   "size": 11438133
  }
 ],
 "after": [
  "Restart the PC, then run this tool again: it should report nothing.",
  "Delete the installer you downloaded (the game / app zip or Setup.exe).",
  "From another, clean device, change the passwords of the accounts used on this PC (email first, then Discord, Steam, banking), sign out all other sessions and turn on two-factor sign-in.",
  "In Discord: change your password (this also signs out the stolen login)."
 ],
 "beta": true
}
'@
$Sig = $SignatureJson | ConvertFrom-Json
$ErrorActionPreference = 'Continue'
$script:found = 0; $script:failed = 0; $script:reset = 0; $script:kept = 0
function Say([string]$s) { [Console]::WriteLine($s) }
function Note([string]$what) { $script:found++; Say ("[found] " + $what) }
function Act([string]$what, [scriptblock]$do) {
    if (-not $Apply) { Say ("[would] " + $what); return }
    try { & $do; Say ("[done]  " + $what) } catch { $script:failed++; Say ("[fail]  " + $what + ": " + $_) }
}
# Settings the malware's operators can change are always put back to Windows defaults,
# infected or not: they are counted apart from infection findings.
function Reset([string]$what, [scriptblock]$do) { $script:reset++; Say ("[reset] " + $what); Act ("reset " + $what) $do }
function Under([string]$path, [string]$dir) { $path -and $dir -and $path.StartsWith($dir.TrimEnd('\') + '\', 'OrdinalIgnoreCase') }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Say "Note: not running as administrator; some items may not be removable (right-click > Run as administrator)." }
Say ("{0} removal{3}, signature v{1} ({2})" -f $Sig.family, $Sig.version, $(if ($Apply) { 'REMOVING' } else { 'check only' }), $(if ($Sig.beta) { ' (BETA)' } else { '' }))
Say ""

# ---- profiles (and their registry hive, when loaded)
$profiles = @()
$cur = [Environment]::GetFolderPath('UserProfile')
Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) } | ForEach-Object {
    if (-not $CurrentUserOnly -or $_.LocalPath -ieq $cur) {
        $hive = if (Test-Path "Registry::HKEY_USERS\$($_.SID)") { "Registry::HKEY_USERS\$($_.SID)" } else { $null }
        $profiles += [pscustomobject]@{ Home = $_.LocalPath; Hive = $hive }
    }
}
if (-not $profiles.Count) { $profiles += [pscustomobject]@{ Home = $cur; Hive = 'Registry::HKEY_CURRENT_USER' } }
function Expand([string]$t, $p) {
    $t.Replace('{home}', $p.Home).Replace('{local}', (Join-Path $p.Home 'AppData\Local')).Replace('{roaming}', (Join-Path $p.Home 'AppData\Roaming'))
}

# ---- 1. install folders, identified by the files the payload always installs
$dirs = @()     # role, path, name, profile
foreach ($p in $profiles) {
    foreach ($d in $Sig.dirs) {
        $parent = Expand $d.parent $p
        $cands = if ($d.name -eq '*') { Get-ChildItem -LiteralPath $parent -Directory -Force -ErrorAction SilentlyContinue }
                 else { Get-Item -LiteralPath (Join-Path $parent $d.name) -Force -ErrorAction SilentlyContinue }
        foreach ($c in @($cands)) {
            if (-not $c) { continue }
            $ok = $true
            foreach ($a in $d.anchors) { if (-not (Test-Path -LiteralPath (Join-Path $c.FullName $a))) { $ok = $false; break } }
            if ($ok) { $dirs += [pscustomobject]@{ Role = $d.role; Path = $c.FullName; Name = $c.Name; Profile = $p; What = $d.what } }
        }
    }
}
foreach ($d in $dirs) { Note ("{0}: {1}" -f $d.What, $d.Path) }
function InAny([string]$path, [string[]]$roles) { foreach ($d in $dirs) { if ($roles -contains $d.Role -and (Under $path $d.Path)) { return $true } }; return $false }

# ---- 1b. the bot by what its jar contains: any file name, any extension, any folder
# A Java archive is the bot when it carries the kit's Discord gateway library together with its
# stealer libraries and the obfuscator's look-alike class names (I, i, l, 1 only). Names and paths
# play no part, so renamed and moved builds are found too.
Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
$fp = $Sig.fingerprint
$script:jarSeen = @{}
$botJars = New-Object System.Collections.ArrayList        # files identified as the bot
function Test-BotJar([string]$path) {
    if (-not $fp -or -not $path) { return $false }
    $key = $path.ToLowerInvariant()
    if ($script:jarSeen.ContainsKey($key)) { return $script:jarSeen[$key] }
    $hit = $false
    try {
        $fi = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (-not $fi.PSIsContainer -and $fi.Length -ge [long]$fp.min_size -and $fi.Length -le [long]$fp.max_size) {
            $fs = [IO.File]::Open($fi.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
            try {
                $b = New-Object byte[] 2
                if ($fs.Read($b, 0, 2) -eq 2 -and $b[0] -eq 0x50 -and $b[1] -eq 0x4B) {
                    $fs.Position = 0
                    $z = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Read, $true)
                    try {
                        $libsAll = $true; foreach ($l in $fp.libs_all) { if (-not ($z.Entries | Where-Object { $_.FullName.StartsWith($l) } | Select-Object -First 1)) { $libsAll = $false; break } }
                        $libsAny = $false; foreach ($l in $fp.libs_any) { if ($z.Entries | Where-Object { $_.FullName.StartsWith($l) } | Select-Object -First 1) { $libsAny = $true; break } }
                        $obf = @($z.Entries | Where-Object { $_.FullName -cmatch $fp.obf_class_rx }).Count
                        $main = $false
                        $mf = $z.GetEntry('META-INF/MANIFEST.MF')
                        if ($mf) { $r = New-Object IO.StreamReader($mf.Open()); try { $main = $r.ReadToEnd() -cmatch $fp.obf_main_rx } finally { $r.Dispose() } }
                        $hit = $libsAll -and $libsAny -and ($obf -ge [int]$fp.obf_min_classes -or $main)
                    } finally { $z.Dispose() }
                }
            } finally { $fs.Dispose() }
        }
    } catch {}
    $script:jarSeen[$key] = $hit
    return $hit
}
# folders a bot file may sit in that must never be deleted as a whole
$keepDirs = @($env:SystemRoot, $env:ProgramData, $env:PUBLIC, ${env:ProgramFiles}, ${env:ProgramFiles(x86)})
foreach ($p in $profiles) {
    $keepDirs += $p.Home
    foreach ($sub in 'AppData', 'AppData\Local', 'AppData\Roaming', 'AppData\LocalLow', 'AppData\Local\Temp', 'AppData\Local\Programs',
                     'Desktop', 'Downloads', 'Documents', 'Music', 'Pictures', 'Videos', 'Saved Games', 'OneDrive',
                     'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') { $keepDirs += (Join-Path $p.Home $sub) }
}
function Is-KeepDir([string]$d) { foreach ($k in $keepDirs) { if ($k -and $d.TrimEnd('\') -ieq $k.TrimEnd('\')) { return $true } }; return $false }
function Has-Jre([string]$d) {          # a Java runtime the kit ships with its bot (java\bin\javaw.exe, renamed or not)
    foreach ($c in @(Get-ChildItem -LiteralPath $d -Directory -Force -ErrorAction SilentlyContinue)) {
        if ((Test-Path -LiteralPath (Join-Path $c.FullName 'bin\javaw.exe')) -or (Test-Path -LiteralPath (Join-Path $c.FullName 'lib\modules'))) { return $true }
    }
    return $false
}
function Add-BotJar([string]$path, [string]$how) {
    $full = (Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue).FullName
    if (-not $full -or @($botJars | Where-Object { $_ -ieq $full }).Count) { return }
    [void]$botJars.Add($full)
    Note ("the remote-control bot (Java, identified by its contents; {0}): {1}" -f $how, $full)
    $dir = Split-Path -Parent $full
    if (InAny $full @('bot', 'app')) { return }
    $prof = $profiles | Where-Object { Under $full $_.Home } | Select-Object -First 1
    # inside a fake app (resources\ next to app.asar): the whole app goes
    if ((Split-Path -Leaf $dir) -ieq 'resources' -and (Test-Path -LiteralPath (Join-Path $dir 'app.asar'))) {
        $app = Split-Path -Parent $dir
        if (-not (Is-KeepDir $app)) { $script:dirs += [pscustomobject]@{ Role = 'app'; Path = $app; Name = (Split-Path -Leaf $app); Profile = $prof; What = 'the fake game / app that carries the bot' }; Note "the fake game / app that carries the bot: $app"; return }
    }
    # its own folder (the jar next to the bundled Java runtime): the folder goes; else only the file
    if (-not (Is-KeepDir $dir) -and (Has-Jre $dir)) {
        $script:dirs += [pscustomobject]@{ Role = 'bot'; Path = $dir; Name = (Split-Path -Leaf $dir); Profile = $prof; What = 'the remote-control bot folder (with its own Java)' }
        Note "the remote-control bot folder (with its own Java): $dir"
    }
}
# jar paths named in a command line: -jar X, -cp / -classpath X;Y, or any quoted / bare existing file
function Get-CmdJars([string]$cl) {
    $out = @()
    if (-not $cl) { return $out }
    foreach ($m in [regex]::Matches($cl, '(?i)(?:-jar|-cp|-classpath|--class-path)\s+(?:"([^"]+)"|(\S+))')) {
        $v = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        $out += ($v -split ';')
    }
    foreach ($m in [regex]::Matches($cl, '"([^"]+)"')) { $out += $m.Groups[1].Value }
    foreach ($t in ($cl -split '\s+')) { if ($t -match '(?i)\.jar$') { $out += $t.Trim('"') } }
    return @($out | Where-Object { $_ -and $_ -notmatch '(?i)\.exe$' } | Select-Object -Unique)
}
# search: every .jar, plus every file sitting next to a bundled Java runtime (any extension)
foreach ($p in $profiles) {
    $roots = @('AppData\Local', 'AppData\Roaming', 'AppData\LocalLow', 'Desktop', 'Downloads', 'Documents', 'Music', 'Pictures', 'Videos', 'Saved Games') |
             ForEach-Object { Join-Path $p.Home $_ } | Where-Object { Test-Path -LiteralPath $_ }
    foreach ($r in $roots) {
        Get-ChildItem -Path $r -Recurse -Force -File -Include '*.jar', 'javaw.exe' -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Name -ieq 'javaw.exe' -and (Split-Path -Leaf $_.DirectoryName) -ieq 'bin') {
                $home2 = Split-Path -Parent (Split-Path -Parent $_.DirectoryName)          # the folder holding the runtime
                Get-ChildItem -LiteralPath $home2 -File -Force -ErrorAction SilentlyContinue | ForEach-Object { if (Test-BotJar $_.FullName) { Add-BotJar $_.FullName 'next to a bundled Java runtime' } }
            } elseif (Test-BotJar $_.FullName) { Add-BotJar $_.FullName 'found on disk' }
        }
    }
}
foreach ($r in @($env:ProgramData, $env:PUBLIC)) {
    if ($r -and (Test-Path -LiteralPath $r)) { Get-ChildItem -LiteralPath $r -Recurse -Force -File -Filter '*.jar' -ErrorAction SilentlyContinue | ForEach-Object { if (Test-BotJar $_.FullName) { Add-BotJar $_.FullName 'found on disk' } } }
}

# ---- 2. running processes
$rx = $Sig.process_cmdline
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    $pr = $_; $cl = [string]$pr.CommandLine; $ep = [string]$pr.ExecutablePath
    $viaJar = $false
    foreach ($j in (Get-CmdJars $cl)) { if (Test-BotJar $j) { Add-BotJar $j "run by process $($pr.ProcessId)"; $viaJar = $true } }
    if ($viaJar -or ($rx -and $cl -match $rx) -or (InAny $ep @($Sig.process_roles)) -or @($botJars | Where-Object { $cl -like "*$_*" }).Count) {
        Note ("running: {0} (pid {1}) {2}" -f $pr.Name, $pr.ProcessId, $cl)
        Act ("stop pid " + $pr.ProcessId) { Stop-Process -Id $pr.ProcessId -Force -ErrorAction Stop }
    }
}

# ---- 3. start-up entries
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $t = $_
    foreach ($a in @($t.Actions)) {
        $line = "" + $a.Execute + " " + $a.Arguments
        $jarHit = $false; foreach ($j in (Get-CmdJars $line)) { if (Test-BotJar $j) { Add-BotJar $j "started by task $($t.TaskName)"; $jarHit = $true } }
        if ($jarHit -or $line -match $Sig.task_action -or @($botJars | Where-Object { $line -like "*$_*" }).Count -or (InAny ([string]$a.Execute).Trim('"') @('bot', 'app'))) {
            Note ("start-up task: {0}{1} -> {2} {3}" -f $t.TaskPath, $t.TaskName, $a.Execute, $a.Arguments)
            Act ("delete task " + $t.TaskPath + $t.TaskName) { Unregister-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -Confirm:$false -ErrorAction Stop }
            break
        }
    }
}
$runKeys = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
foreach ($p in $profiles) { if ($p.Hive) { $runKeys += "$($p.Hive)\Software\Microsoft\Windows\CurrentVersion\Run" } }
foreach ($rk in $runKeys) {
    $k = Get-Item -LiteralPath $rk -ErrorAction SilentlyContinue; if (-not $k) { continue }
    foreach ($n in $k.Property) {
        $v = [string]$k.GetValue($n)
        $jarHit = $false; foreach ($j in (Get-CmdJars $v)) { if (Test-BotJar $j) { Add-BotJar $j "started by $rk\$n"; $jarHit = $true } }
        if ($jarHit -or $v -match $Sig.task_action -or @($dirs | Where-Object { $v -like ('*' + $_.Path + '*') }).Count) {
            Note "start-up entry: $rk\$n = $v"
            Act "delete $rk\$n" { Remove-ItemProperty -LiteralPath $rk -Name $n -Force -ErrorAction Stop }
        }
    }
}
foreach ($p in $profiles) {
    $su = Join-Path $p.Home 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    Get-ChildItem -LiteralPath $su -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $f = $_.FullName; $txt = ''
        if ($_.Extension -eq '.lnk') { $s = (New-Object -ComObject WScript.Shell).CreateShortcut($f); $txt = $s.TargetPath + ' ' + $s.Arguments }
        elseif ($_.Length -lt 65536) { $txt = Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue }
        $jarHit = $false; foreach ($j in (Get-CmdJars $txt)) { if (Test-BotJar $j) { Add-BotJar $j "started by $f"; $jarHit = $true } }
        if ($jarHit -or $txt -match $Sig.task_action) { Note "start-up item: $f"; Act "delete $f" { Remove-Item -LiteralPath $f -Force -ErrorAction Stop } }
    }
}

# ---- 4. "Apps & features" entries and shortcuts pointing into the install folders
foreach ($p in $profiles) {
    $hk = @(); if ($p.Hive) { $hk += "$($p.Hive)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    foreach ($u in $hk) {
        Get-ChildItem -LiteralPath $u -ErrorAction SilentlyContinue | ForEach-Object {
            $s = [string]$_.GetValue('UninstallString') + ' ' + [string]$_.GetValue('DisplayIcon') + ' ' + [string]$_.GetValue('InstallLocation')
            if (@($dirs | Where-Object { $Sig.uninstall_roles -contains $_.Role -and $s -like ('*' + $_.Path + '*') }).Count) {
                $key = $_.PSPath
                Note ("Apps & features entry: {0} {1} ({2})" -f $_.GetValue('DisplayName'), $_.GetValue('DisplayVersion'), $_.PSChildName)
                Act ("delete entry " + $_.PSChildName) { Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop }
            }
        }
    }
}
$wsh = New-Object -ComObject WScript.Shell
$places = @()
foreach ($p in $profiles) { foreach ($pl in $Sig.shortcut_places) { $places += (Expand $pl $p) } }
$places += [Environment]::GetFolderPath('CommonDesktopDirectory'); $places += [Environment]::GetFolderPath('CommonPrograms')
foreach ($pl in ($places | Select-Object -Unique)) {
    Get-ChildItem -LiteralPath $pl -Filter *.lnk -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $tgt = $wsh.CreateShortcut($_.FullName).TargetPath
        if (InAny $tgt @($Sig.shortcut_roles)) { $f = $_.FullName; Note "shortcut: $f -> $tgt"; Act "delete $f" { Remove-Item -LiteralPath $f -Force -ErrorAction Stop } }
    }
}

# ---- 5. side folders named after the install folder (updater, app data)
foreach ($d in @($dirs)) {
    foreach ($sb in @($Sig.siblings | Where-Object { $_.of -eq $d.Role })) {
        $path = (Expand $sb.path $d.Profile).Replace('{name}', $d.Name)
        if (Test-Path -LiteralPath $path) { Note ("{0}: {1}" -f $sb.what, $path); $dirs += [pscustomobject]@{ Role = 'sibling'; Path = $path; Name = ''; Profile = $d.Profile; What = $sb.what } }
    }
}

# ---- 6. temp files, only where the payload's own marker proves it ran
foreach ($p in $profiles) {
    $tmp = Join-Path $p.Home 'AppData\Local\Temp'
    $gate = @($Sig.temp.gate | Where-Object { Test-Path -LiteralPath (Join-Path $tmp $_) })
    $gate += @($Sig.temp.gate_globs | ForEach-Object { Get-ChildItem -LiteralPath $tmp -Filter $_ -Force -ErrorAction SilentlyContinue })
    if (-not $gate.Count -and -not $botJars.Count -and -not $dirs.Count) { continue }
    Get-ChildItem -LiteralPath $tmp -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $n = $_.Name
        if (@($Sig.temp.globs | Where-Object { $n -like $_ }).Count) { $f = $_.FullName; Note "temp: $f"; Act "delete $f" { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction Stop } }
    }
}

# ---- 7. delete the install folders and bot files (after the processes are gone)
if ($Apply) { Start-Sleep -Seconds 2 }
foreach ($d in $dirs) { $path = $d.Path; Act "delete folder $path" { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop } }
foreach ($j in @($botJars)) { if (-not (InAny $j @('bot', 'app', 'sibling'))) { $jj = $j; Act "delete $jj" { Remove-Item -LiteralPath $jj -Force -ErrorAction Stop } } }

# ---- 8. settings: policies, Defender, recovery (always reset), and what the commands change
$infected = ($dirs.Count -gt 0) -or ($botJars.Count -gt 0)
# Windows Recovery on or off, in any Windows language: ReAgent.xml's InstallState (1 = enabled);
# reagentc's text (English) only as a fallback. 'unknown' = leave it alone.
function WinRE-State {
    $xmlPath = Join-Path $env:SystemRoot "System32\Recovery\ReAgent.xml"
    try {
        [xml]$x = Get-Content -LiteralPath $xmlPath -Raw -ErrorAction Stop
        $st = $x.WindowsRE.InstallState.state
        if ($st -eq '1') { return 'enabled' } elseif ($st -eq '0') { return 'disabled' }
    } catch {}
    $re = (& reagentc.exe /info 2>$null) | Out-String
    if ($re -match 'Windows RE status:\s+Enabled') { return 'enabled' }
    if ($re -match 'Windows RE status:\s+Disabled') { return 'disabled' }
    return 'unknown'
}
function PolicyValue($root, $key, $name, $default, $what) {
    $k = "$root\$key"
    $v = (Get-ItemProperty -LiteralPath $k -Name $name -ErrorAction SilentlyContinue).$name
    if ($null -eq $v) { return }
    if ($null -eq $default) {
        Reset ("{0}: {1}\{2} = {3} (remove)" -f $what, $key, $name, $v) { Remove-ItemProperty -LiteralPath $k -Name $name -Force -ErrorAction Stop }
    } elseif (("" + $v) -ne ("" + $default)) {
        Reset ("{0}: {1}\{2} = {3} (set {4})" -f $what, $key, $name, $v, $default) { Set-ItemProperty -LiteralPath $k -Name $name -Value ([int]$default) -Type DWord -ErrorAction Stop }
    }
}
foreach ($e in $Sig.effects) {
    switch ($e.kind) {
        { $_ -in 'regvalue', 'policy' } {
            $default = if ($e.kind -eq 'policy') { $e.default } else { $null }
            if ($e.hive -eq 'HKCU') { foreach ($p in $profiles) { if ($p.Hive) { PolicyValue $p.Hive $e.key $e.name $default $e.what } } }
            else { PolicyValue 'Registry::HKEY_LOCAL_MACHINE' $e.key $e.name $default $e.what }
        }
        'policy_key' {          # a whole policy key back to "not configured" (e.g. Windows Defender policies)
            $k = "Registry::HKEY_LOCAL_MACHINE\$($e.key)"
            $it = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
            # Windows ships this key with an empty "Policy Manager" subkey: only values anywhere in it count
            $sub = @(Get-ChildItem -LiteralPath $k -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Property.Count })
            if ($it -and ($it.Property.Count -or $sub.Count)) {
                $desc = @($it.Property | ForEach-Object { "$_=" + $it.GetValue($_) }) + @($sub | ForEach-Object { $_.PSChildName + '\' + ($_.Property -join ',') })
                Reset ("{0}: HKLM\{1} [{2}] (remove)" -f $e.what, $e.key, ($desc -join '; ')) { Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction Stop }
            }
        }
        'policy_key_if_empty' {
            if (-not $infected) { break }        # an empty key is harmless: only tidy up after an infection
            foreach ($p in $profiles) {
                if (-not $p.Hive) { continue }
                $k = "$($p.Hive)\$($e.key)"
                $it = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
                # empty now, or about to be once this run's resets of its values are applied
                $left = @($it.Property | Where-Object { $n = $_; -not @($Sig.effects | Where-Object { $_.kind -eq 'policy' -and $_.hive -eq 'HKCU' -and $_.key -eq $e.key -and $_.name -eq $n -and $null -eq $_.default }).Count })
                if ($it -and -not $left.Count -and $it.SubKeyCount -eq 0) {
                    $kk = $k; Reset ("{0}: HKCU\{1} (remove)" -f $e.what, $e.key) { Remove-Item -LiteralPath $kk -Force -ErrorAction Stop }
                }
            }
        }
        'defender' {
            try { $mp = Get-MpPreference -ErrorAction Stop } catch { Say "[info]  Microsoft Defender not available (another antivirus?); skipped"; break }
            foreach ($kind in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress') {
                foreach ($x in @($mp.$kind)) {
                    if (-not $x -or $x -like 'N/A*') { continue }
                    $xx = $x; $kk = $kind
                    Reset "Defender ${kind}: $x (remove)" { $a = @{ $kk = $xx }; Remove-MpPreference @a -ErrorAction Stop }
                }
            }
            foreach ($n in 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning', 'DisableBlockAtFirstSeen') {
                if ($mp.$n -eq $true) { $nn = $n; Reset "Defender $n = True (set False)" { $a = @{ $nn = $false }; Set-MpPreference @a -ErrorAction Stop } }
            }
            if ($mp.MAPSReporting -eq 0) { Reset "Defender cloud protection off (MAPSReporting 0, set 2)" { Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop } }
            if ($mp.SubmitSamplesConsent -eq 2) { Reset "Defender sample submission never (set: send safe samples)" { Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop } }
            if ($Apply) {               # tamper protection can silently refuse: check
                $mp2 = Get-MpPreference -ErrorAction SilentlyContinue
                if ($mp2 -and (@($mp2.ExclusionPath | Where-Object { $_ -and $_ -notlike 'N/A*' }).Count -or $mp2.DisableRealtimeMonitoring)) {
                    $script:failed++; Say "[fail]  Defender still has exclusions or real-time protection off (tamper protection?). Open Windows Security > Virus & threat protection to fix it by hand."
                }
            }
        }
        'winre' {
            if (-not $admin) { Say "[info]  Windows Recovery not checked (needs administrator)"; break }
            if ((WinRE-State) -eq 'disabled') {
                # EXPERIMENTAL. The gang's !sifirlama runs "reagentc /disable" (which keeps the image
                # in System32\Recovery\Winre.wim); /enable undoes it. If Windows lost track of the
                # image, point it back there first. Only counted as done once Recovery reads as on.
                Reset ($e.what + " [experimental re-enable]") {
                    & reagentc.exe /enable 2>&1 | Out-Null
                    if ((WinRE-State) -ne 'enabled') {
                        $img = Join-Path $env:SystemRoot "System32\Recovery"
                        if (Test-Path -LiteralPath (Join-Path $img "Winre.wim")) {
                            & reagentc.exe /setreimage /path $img 2>&1 | Out-Null
                            & reagentc.exe /enable 2>&1 | Out-Null
                        }
                    }
                    $now = WinRE-State
                    if ($now -ne 'enabled') { throw "Windows Recovery is still $now after reagentc /enable (see: reagentc /info)" }
                }
            }
        }
        'file_restore' {
            foreach ($p in $profiles) {
                Get-ChildItem -Path (Expand $e.glob $p) -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    $txt = (Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue)
                    if ($null -ne $txt -and $txt.Trim() -ne $e.clean) {
                        $f = $_.FullName; Note "$($e.what): $f"
                        Act "restore $f" { Set-Content -LiteralPath $f -Value $e.clean -NoNewline -Encoding ASCII -ErrorAction Stop }
                    }
                }
            }
        }
        'dropped_exe' {
            # programs the operators download onto the PC (!cookie saves them in %LOCALAPPDATA% after excluding
            # it from Defender): any .exe named like a Windows system program outside Windows (always), and,
            # on an infected PC, any .exe lying loose at the top of AppData\Local / Roaming / LocalLow / Temp
            foreach ($p in $profiles) {
                foreach ($sub in $e.places) {
                    $dir = Expand $sub $p
                    Get-ChildItem -LiteralPath $dir -File -Force -Filter '*.exe' -ErrorAction SilentlyContinue | ForEach-Object {
                        $masq = $_.BaseName -match $e.masquerade_rx
                        if (-not ($masq -or $infected)) { return }
                        $f = $_.FullName
                        $sigOk = (Get-AuthenticodeSignature -LiteralPath $f -ErrorAction SilentlyContinue).Status -eq 'Valid'
                        if ($sigOk -and -not $masq) { return }           # a signed program from a real publisher: leave it
                        Note ("{0}: {1}{2}" -f $e.what, $f, $(if ($masq) { ' (named like a Windows program)' } else { '' }))
                        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -ieq $f } | ForEach-Object {
                            $pid2 = $_.ProcessId; Act "stop pid $pid2" { Stop-Process -Id $pid2 -Force -ErrorAction Stop } }
                        Act "delete $f" { Remove-Item -LiteralPath $f -Force -ErrorAction Stop }
                    }
                }
            }
        }
        'report_files' {
            foreach ($p in $profiles) {
                $n = @(Get-ChildItem -LiteralPath $p.Home -Recurse -Force -Filter $e.glob -ErrorAction SilentlyContinue).Count
                # left in place on purpose (they can be decrypted): not an infection finding
                if ($n) { $script:kept += $n; Say ("[keep]  {0}: {1} file(s) under {2} (left in place) {3}" -f $e.what, $n, $p.Home, $e.advice) }
            }
        }
    }
}

Say ""
if (-not $script:found) { Say "No sign of $($Sig.family) on this PC." }
else { Say "$($script:found) infection item(s) found." }
if ($script:reset) { Say "$($script:reset) security setting(s) not at the Windows default (reset by -Apply)." }
if ($script:kept) { Say "$($script:kept) encrypted file(s) left in place: keep them, they can be decrypted." }
if (-not $Apply) { if ($script:found -or $script:reset) { Say "Nothing was changed. Run again with -Apply to remove / reset them." } }
else {
    Say ("Done: {0} item(s) removed, {1} setting(s) reset, {2} failed." -f $script:found, $script:reset, $script:failed)
    if ($script:failed) { Say "Some items could not be removed: restart the PC and run this tool again. If [fail] lines remain, send this output to whoever gave you the tool." }
    if ($script:found) { foreach ($l in $Sig.after) { Say $l } }
}
Say ("RESULT found={0} reset={1} failed={2} kept={3} applied={4}" -f $script:found, $script:reset, $script:failed, $script:kept, [int][bool]$Apply)
if ($Pause) { Read-Host "Press Enter to close" | Out-Null }
# exit code: 0 nothing to do, 2 something found / reset, 3 something could not be removed or reset
if ($script:failed) { exit 3 } elseif ($script:found -or $script:reset) { exit 2 } else { exit 0 }
