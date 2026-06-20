function Get-RiskScore {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Path,
        [string]$SHA256,
        [string]$Publisher,
        [string]$RemoteAddress,
        [int]$RemotePort,
        [string]$CommandLine
    )

    $configFile = "$script:SentinelDir\sentinel-config.json"
    $config = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $weights = $config.risk_weights
    $score = 0

    $sig = Get-ProcessSignature -Path $Path
    $fileInfo = if ($Path -and (Test-Path $Path)) { Get-Item $Path -ErrorAction SilentlyContinue } else { $null }

    if ($sig.Status -eq "Valid") {
        if ($sig.Signer -match "Microsoft") { $score += [int]$weights.signed_microsoft }
        else { $score += [int]$weights.signed_other }
    } elseif ($sig.Status -eq "NotSigned" -or $sig.Status -eq "NoPath") {
        $score += [int]$weights.no_signature
    } elseif ($sig.Status -eq "HashMismatch" -or $sig.Status -eq "NotTrusted") {
        $score += [int]$weights.invalid_signature
    }

    if ($Publisher) {
        $knownPublishers = $config.never_auto_block.publishers
        foreach ($kp in $knownPublishers) {
            if ($Publisher -match [regex]::Escape($kp)) { $score += [int]$weights.publisher_known; break }
        }
    }

    if ($Path) {
        $pathLower = $Path.ToLower()
        if ($pathLower -match '^c:\\program files\\') { $score += [int]$weights.path_program_files }
        elseif ($pathLower -match '^c:\\windows\\system32\\') { $score += [int]$weights.path_system32 }
        elseif ($pathLower -match '^c:\\program files\\(x86)\\' -or $pathLower -match 'windowsapps') { $score += [int]$weights.path_windowsapps }
        elseif ($pathLower -match '\\temp\\' -or $pathLower -match '\\tmp\\') { $score += [int]$weights.path_temp }
        elseif ($pathLower -match '\\downloads\\') { $score += [int]$weights.path_downloads }
        elseif ($pathLower -match '\\appdata\\local\\temp\\') { $score += [int]$weights.path_appdata_temp }
    }

    if ($fileInfo -and $fileInfo.CreationTime) {
        $age = (Get-Date) - $fileInfo.CreationTime
        if ($age.TotalDays -le 1) { $score += [int]$weights.created_last_24h }
        elseif ($age.TotalDays -le 7) { $score += [int]$weights.created_last_7days }
    }

    $isApproved = Test-IsApprovedApp -SHA256 $SHA256 -Path $Path
    if ($isApproved) { $score += [int]$weights.approved_by_user }

    $reputation = Get-KnownReputation
    $repEntry = $reputation | Where-Object { $_.SHA256 -eq $SHA256 -or ($_.Name -eq $ProcessName -and $_.Path -eq $Path) }
    if ($repEntry) {
        $count = [int]$repEntry.Count
        if ($count -ge 20) { $score += [int]$weights.reputation_20plus }
        elseif ($count -ge 5) { $score += [int]$weights.reputation_5plus }
    }

    $whitelistScore = Get-WhitelistPathScore -ProcessName $ProcessName
    $score += $whitelistScore

    $isProtected = Test-IsInProtectionList -ProcessName $ProcessName -Path $Path -Publisher $Publisher
    if ($isProtected -and $score -lt 50) { $score = 50 }

    $isDevMode = Test-IsDevModePath -Path $Path
    if ($isDevMode) {
        $devConfig = $config.dev_mode
        if ($devConfig.ignore_absence_of_signature -and $sig.Status -eq "NotSigned") { }
        if ($devConfig.ignore_recent_creation -and $fileInfo -and ((Get-Date) - $fileInfo.CreationTime).TotalDays -le 1) { }
    }

    if ($score -gt 100) { $score = 100 }
    if ($score -lt -100) { $score = -100 }

    return $score
}

function Classify-Risk {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Path,
        [string]$SHA256,
        [string]$Publisher,
        [string]$RemoteAddress,
        [int]$RemotePort,
        [string]$CommandLine
    )

    $score = Get-RiskScore @PSBoundParameters
    $level = Get-RiskLevel -Score $score

    return [PSCustomObject]@{
        Score = $score
        Level = $level
        Color = Get-RiskColor -Level $level
        Icon = Get-RiskIcon -Level $level
        ProcessName = $ProcessName
        Path = $Path
        SHA256 = $SHA256
        Publisher = $Publisher
    }
}

function Get-ProcessRiskDetails {
    param([int]$ProcessId)

    $details = Get-ProcessDetails -ProcessId $ProcessId
    if (-not $details) { return $null }

    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -eq $PID } |
        Select-Object @{N='RemoteAddress';E={$_.RemoteAddress}}, @{N='RemotePort';E={$_.RemotePort}}

    $primaryConn = $connections | Select-Object -First 1

    $classification = Classify-Risk -ProcessId $details.ProcessId -ProcessName $details.ProcessName -Path $details.Path -SHA256 $details.SHA256 -Publisher $details.Company -RemoteAddress $primaryConn.RemoteAddress -RemotePort $primaryConn.RemotePort -CommandLine $details.CommandLine

    return [PSCustomObject]@{
        Process = $details
        Connections = $connections
        Classification = $classification
    }
}
