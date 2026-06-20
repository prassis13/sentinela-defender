$script:BaseDir = "C:\Users\AKALM\seguranca"
$script:SentinelDir = "$script:BaseDir\sentinel"
$script:DataDir = "$script:SentinelDir\data"
$script:ReputationDir = "$script:DataDir\reputation"
$script:AlertsDir = "$script:DataDir\alerts"
$script:ConfigDir = "$script:DataDir\config"
$script:EvidenceDir = "$script:SentinelDir\evidence"
$script:LogDir = "$script:BaseDir\log"

function Get-SentinelTimestamp {
    return Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

function Get-SentinelTimestampFile {
    return Get-Date -Format "yyyyMMdd-HHmmss"
}

function Write-SentinelLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-SentinelTimestamp
    $logLine = "[$timestamp] [$Level] $Message"
    $logFile = "$script:LogDir\sentinel.log"
    Add-Content -Path $logFile -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    if ($Level -eq "ERROR" -or $Level -eq "WARN") {
        Write-Host $logLine -ForegroundColor Yellow
    }
}

function Get-FileHashSHA256 {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try {
        $hash = Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash.ToLower()
    } catch {
        return $null
    }
}

function Get-ProcessSignature {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return @{Status = "NotFound"; Signer = $null } }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        return @{
            Status = $sig.Status.ToString()
            Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
            IsOSBinary = $sig.IsOSBinary
        }
    } catch {
        return @{Status = "Error"; Signer = $null }
    }
}

function Get-ProcessDetails {
    param([int]$ProcessId)
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) { return $null }
        $path = $proc.Path
        if ([string]::IsNullOrEmpty($path)) { return $null }
        if (-not (Test-Path $path)) { return $null }
        $details = [PSCustomObject]@{
            ProcessId = $ProcessId
            ProcessName = $proc.ProcessName
            Path = $path
            Company = $proc.Company
            FileVersion = if ($path) { (Get-Item $path -ErrorAction SilentlyContinue).VersionInfo.FileVersion } else { $null }
            ProductVersion = if ($path) { (Get-Item $path -ErrorAction SilentlyContinue).VersionInfo.ProductVersion } else { $null }
            SHA256 = if ($path) { Get-FileHashSHA256 -Path $path } else { $null }
            Signature = if ($path) { Get-ProcessSignature -Path $path } else { @{Status = "NoPath"} }
            CreationTime = if ($path) { (Get-Item $path -ErrorAction SilentlyContinue).CreationTime } else { $null }
            CommandLine = $proc.CommandLine
            StartTime = $proc.StartTime
            ParentPID = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue).ParentProcessId
        }
        return $details
    } catch {
        return $null
    }
}

function Get-RiskLevel {
    param([int]$Score)
    switch ($Score) {
        { $_ -ge 50 } { return "safe" }
        { $_ -ge 20 } { return "known" }
        { $_ -ge -20 } { return "caution" }
        { $_ -ge -50 } { return "high_risk" }
        default { return "critical" }
    }
}

function Get-RiskColor {
    param([string]$Level)
    switch ($Level) {
        "safe" { return "#4ec9b0" }
        "known" { return "#6bcf7f" }
        "caution" { return "#ffd700" }
        "high_risk" { return "#ff8c00" }
        "critical" { return "#ff4444" }
        default { return "#888888" }
    }
}

function Get-RiskIcon {
    param([string]$Level)
    switch ($Level) {
        "safe" { return "🟢" }
        "known" { return "🔵" }
        "caution" { return "🟡" }
        "high_risk" { return "🟠" }
        "critical" { return "🔴" }
        default { return "⚪" }
    }
}

function Get-ApprovedApps {
    $file = "$script:ReputationDir\approved_apps.json"
    if (Test-Path $file) {
        try { return Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return @() }
    }
    return @()
}

function Save-ApprovedApps {
    param($Apps)
    $file = "$script:ReputationDir\approved_apps.json"
    $Apps | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
}

function Get-KnownReputation {
    $file = "$script:ReputationDir\known_apps.json"
    if (Test-Path $file) {
        try { return Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return @() }
    }
    return @()
}

function Save-KnownReputation {
    param($Apps)
    $file = "$script:ReputationDir\known_apps.json"
    $Apps | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
}

function Update-AppReputation {
    param([string]$Name, [string]$Path, [string]$SHA256, [string]$Publisher)

    $reputation = Get-KnownReputation
    $existing = $reputation | Where-Object { $_.SHA256 -eq $SHA256 -or ($_.Name -eq $Name -and $_.Path -eq $Path) }

    if ($existing) {
        $existing.Count = [int]$existing.Count + 1
        $existing.LastSeen = Get-SentinelTimestamp
    } else {
        $entry = [PSCustomObject]@{
            Name = $Name
            Path = $Path
            SHA256 = $SHA256
            Publisher = $Publisher
            FirstSeen = Get-SentinelTimestamp
            LastSeen = Get-SentinelTimestamp
            Count = 1
        }
        $reputation += $entry
    }

    Save-KnownReputation -Apps $reputation
}

function Add-Alert {
    param(
        [string]$ProcessName,
        [string]$Path,
        [string]$SHA256,
        [string]$RiskLevel,
        [int]$Score,
        [string]$RemoteAddress,
        [int]$RemotePort,
        [string]$Summary,
        [int]$ProcessId
    )
    $alerts = Get-AlertHistory
    $alert = [PSCustomObject]@{
        Timestamp = Get-SentinelTimestamp
        ProcessName = $ProcessName
        Path = $Path
        SHA256 = $SHA256
        RiskLevel = $RiskLevel
        Score = $Score
        RemoteAddress = $RemoteAddress
        RemotePort = $RemotePort
        Summary = $Summary
        PID = $ProcessId
        ID = [guid]::NewGuid().ToString().Substring(0, 8)
    }
    $alerts = @($alert) + $alerts
    if ($alerts.Count -gt 500) { $alerts = $alerts[0..499] }
    Save-AlertHistory -Alerts $alerts
}

function Get-AlertHistory {
    $file = "$script:AlertsDir\alert_history.json"
    if (Test-Path $file) {
        try { return Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return @() }
    }
    return @()
}

function Save-AlertHistory {
    param($Alerts)
    $file = "$script:AlertsDir\alert_history.json"
    $Alerts | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
}

function Get-PendingAlerts {
    $file = "$script:ReputationDir\pending_alerts.json"
    if (Test-Path $file) {
        try {
            $result = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($result -is [System.Collections.IEnumerable]) { return @($result) }
            return @()
        } catch { return @() }
    }
    return @()
}

function Save-PendingAlerts {
    param($Alerts)
    $file = "$script:ReputationDir\pending_alerts.json"
    $Alerts | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
}

function Add-PendingAlert {
    param($Alert)
    $pending = @(Get-PendingAlerts)
    $pending += $Alert
    Save-PendingAlerts -Alerts $pending
}

function Clear-PendingAlerts {
    @() | ConvertTo-Json | Set-Content -Path "$script:ReputationDir\pending_alerts.json" -Encoding UTF8
}

function Read-Whitelist {
    $file = "$script:BaseDir\whitelist.txt"
    $list = @()
    if (Test-Path $file) {
        Get-Content $file | ForEach-Object {
            $line = $_.Trim().ToLower()
            if ($line -ne "" -and -not $line.StartsWith("#")) {
                $list += ($line -replace '\.exe$', '')
            }
        }
    }
    return $list
}

function Test-IsInProtectionList {
    param([string]$ProcessName, [string]$Path, [string]$Publisher)

    $config = Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $neverBlock = $config.never_auto_block

    $nameLower = $ProcessName.ToLower().Replace(".exe", "")

    foreach ($protected in $neverBlock.process_names) {
        if ($nameLower -eq $protected.ToLower()) { return $true }
    }

    foreach ($dir in $neverBlock.directories) {
        if ($Path -and $Path.ToLower().StartsWith($dir.ToLower())) { return $true }
    }

    if ($Publisher) {
        foreach ($pub in $neverBlock.publishers) {
            if ($Publisher -match [regex]::Escape($pub)) { return $true }
        }
    }

    return $false
}

function Test-IsDevModePath {
    param([string]$Path)

    $config = Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $config.dev_mode.enabled) { return $false }

    foreach ($dir in $config.dev_mode.project_directories) {
        if ($Path -and $Path.ToLower().StartsWith($dir.ToLower())) { return $true }
    }
    return $false
}

function Get-WhitelistPathScore {
    param([string]$ProcessName)
    $whitelist = Read-Whitelist
    $nameLower = $ProcessName.ToLower().Replace(".exe", "")
    if ($whitelist -contains $nameLower) { return 30 }
    return 0
}

function Test-IsApprovedApp {
    param([string]$SHA256, [string]$Path)
    if (-not $SHA256) { return $false }
    $approved = Get-ApprovedApps
    $match = $approved | Where-Object { $_.SHA256 -eq $SHA256 -or ($_.Path -eq $Path) }
    return ($match -ne $null)
}

function Export-SentinelState {
    $state = [PSCustomObject]@{
        Timestamp = Get-SentinelTimestamp
        Mode = (Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json).mode
        ActiveConnections = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue).Count
        TotalAlerts = (Get-AlertHistory).Count
        ApprovedApps = (Get-ApprovedApps).Count
        KnownApps = (Get-KnownReputation).Count
    }
    return $state
}
