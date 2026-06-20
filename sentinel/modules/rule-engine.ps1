$script:RulesFile = "$script:SentinelDir\data\config\blocked_rules.json"

function Get-AllowRules {
    $file = "$script:ReputationDir\approved_apps.json"
    if (Test-Path $file) {
        try { return Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return @() }
    }
    return @()
}

function Get-BlockRules {
    if (Test-Path $script:RulesFile) {
        try { return Get-Content $script:RulesFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return @() }
    }
    return @()
}

function Save-BlockRules {
    param($Rules)
    $parent = Split-Path $script:RulesFile -Parent
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $Rules | ConvertTo-Json -Depth 10 | Set-Content $script:RulesFile -Encoding UTF8
}

function Add-AllowRule {
    param([string]$ProcessName, [string]$Path, [string]$SHA256)

    $rules = Get-AllowRules
    $existing = $rules | Where-Object { $_.SHA256 -eq $SHA256 -or ($_.Path -eq $Path) }
    if (-not $existing) {
        $rule = [PSCustomObject]@{
            ProcessName = $ProcessName
            Path = $Path
            SHA256 = $SHA256
            CreatedAt = Get-SentinelTimestamp
            Type = "allow"
        }
        $rules += $rule
        Save-ApprovedApps -Apps $rules
        Write-SentinelLog "Allow rule added: $ProcessName"
    }
}

function Add-BlockRule {
    param([string]$ProcessName, [string]$Path, [string]$SHA256, [int]$DurationHours)

    $rules = Get-BlockRules
    $existing = $rules | Where-Object { $_.Path -eq $Path }
    if (-not $existing) {
        $expiry = if ($DurationHours -gt 0) { (Get-Date).AddHours($DurationHours).ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
        $rule = [PSCustomObject]@{
            ProcessName = $ProcessName
            Path = $Path
            SHA256 = $SHA256
            CreatedAt = Get-SentinelTimestamp
            ExpiresAt = $expiry
            Type = "block"
        }
        $rules += $rule
        Save-BlockRules -Rules $rules

        $ruleName = "Sentinel_Block_$($ProcessName)_$(Get-Random -Minimum 1000 -Maximum 9999)"
        try {
            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $Path -Action Block -ErrorAction SilentlyContinue | Out-Null
            Write-SentinelLog "Block rule added + firewall rule created: $ProcessName"
        } catch {
            Write-SentinelLog "Firewall rule creation failed: $_" -Level "ERROR"
        }
    }
}

function Remove-BlockRule {
    param([string]$Path)

    $rules = Get-BlockRules
    $target = $rules | Where-Object { $_.Path -eq $Path }
    if ($target) {
        $name = $target.ProcessName
        $rules = $rules | Where-Object { $_.Path -ne $Path }
        Save-BlockRules -Rules $rules

        Get-NetFirewallRule -DisplayName "Sentinel_Block_$name*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-SentinelLog "Block rule removed: $name"
    }
}

function Get-ExpiredBlockRules {
    $rules = Get-BlockRules
    $expired = @()
    $active = @()
    foreach ($rule in $rules) {
        if ($rule.ExpiresAt) {
            try {
                $expiry = [datetime]::Parse($rule.ExpiresAt)
                if ((Get-Date) -gt $expiry) {
                    $expired += $rule
                    continue
                }
            } catch {}
        }
        $active += $rule
    }
    if ($expired.Count -gt 0) {
        Save-BlockRules -Rules $active
        foreach ($rule in $expired) {
            $name = $rule.ProcessName
            Get-NetFirewallRule -DisplayName "Sentinel_Block_$name*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-SentinelLog "Expired block rule auto-removed: $name"
        }
    }
    return $expired
}

function Test-IsBlocked {
    param([string]$SHA256, [string]$Path)

    if (-not $SHA256 -and -not $Path) { return $false }
    $blocked = Get-BlockRules
    foreach ($rule in $blocked) {
        if ($rule.ExpiresAt) {
            try {
                if ((Get-Date) -gt [datetime]::Parse($rule.ExpiresAt)) { continue }
            } catch {}
        }
        if ($rule.Path -and $Path -and $rule.Path -eq $Path) { return $true }
        if ($rule.SHA256 -and $SHA256 -and $rule.SHA256 -eq $SHA256) { return $true }
    }
    return $false
}

function Get-AllRules {
    $allows = Get-AllowRules | ForEach-Object {
        [PSCustomObject]@{
            Type = "allow"
            Name = $_.Name
            Path = $_.Path
            CreatedAt = $_.ApprovedAt
        }
    }
    $blocks = Get-BlockRules | ForEach-Object {
        [PSCustomObject]@{
            Type = "block"
            Name = $_.ProcessName
            Path = $_.Path
            CreatedAt = $_.CreatedAt
            ExpiresAt = $_.ExpiresAt
        }
    }
    return $allows + $blocks
}

function Clear-BlockRule {
    param([string]$Path)
    Remove-BlockRule -Path $Path
}
