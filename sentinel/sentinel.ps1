param(
    [switch]$Dashboard,
    [switch]$Tray,
    [switch]$NoTray
)

$ErrorActionPreference = "Stop"
$script:BaseDir = "C:\Users\AKALM\seguranca"
$script:SentinelDir = "$script:BaseDir\sentinel"
$script:ModuleDir = "$script:SentinelDir\modules"

. "$script:ModuleDir\sentinel-utils.ps1"
. "$script:ModuleDir\risk-engine.ps1"
. "$script:ModuleDir\rule-engine.ps1"
. "$script:ModuleDir\sentinel-events.ps1"
. "$script:ModuleDir\sentinel-tray.ps1"
. "$script:ModuleDir\sentinel-dashboard.ps1"

$script:Running = $true
$script:DecisionTimer = $null

function Initialize-SentinelDirs {
    $dirs = @(
        "$script:SentinelDir\data\reputation",
        "$script:SentinelDir\data\alerts",
        "$script:SentinelDir\data\config",
        "$script:SentinelDir\evidence",
        "$script:SentinelDir\backup",
        "$script:BaseDir\log"
    )
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }
}

function Process-PendingDecisions {
    $config = Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $pending = Get-PendingAlerts

    if ($pending.Count -gt 0) {
        Set-TrayAlert -HasAlert $true
    }

    Get-ExpiredBlockRules

    $remaining = @()
    foreach ($alert in $pending) {
        if (Test-IsBlocked -SHA256 $alert.SHA256 -Path $alert.Path) {
            continue
        }

        $shouldPrompt = $true

        if ($config.mode -eq "learn") {
            $shouldPrompt = $false
            Update-AppReputation -Name $alert.ProcessName -Path $alert.Path -SHA256 $alert.SHA256 -Publisher $null
        }

        if ($shouldPrompt -and $config.action_policies.require_confirmation_for -contains $alert.RiskLevel) {
            $approved = $false
            $decisionMade = $false

            Show-TrayDecision -ProcessName $alert.ProcessName -Path $alert.Path -RiskLevel $alert.RiskLevel -Score $alert.Score -Summary $alert.Summary -AllowCallback {
                $script:approved = $true
                $script:decisionMade = $true
            } -BlockCallback {
                $script:approved = $false
                $script:decisionMade = $true
            } -IgnoreCallback {
                $script:decisionMade = $true
            }

            if ($decisionMade) {
                if ($approved) {
                    $apps = Get-ApprovedApps
                    $entry = [PSCustomObject]@{
                        Name = $alert.ProcessName
                        Path = $alert.Path
                        SHA256 = $alert.SHA256
                        ApprovedAt = Get-SentinelTimestamp
                    }
                    $apps += $entry
                    Save-ApprovedApps -Apps $apps
                    Write-SentinelLog "User approved: $($alert.ProcessName)"
                }
            } else {
                $remaining += $alert
            }
        } elseif ($shouldPrompt -and $alert.RiskLevel -eq "critical" -and $config.mode -eq "protect") {
            Write-SentinelLog "[ACTION] Blocking network for critical process: $($alert.ProcessName)"
            Add-BlockRule -ProcessName $alert.ProcessName -Path $alert.Path -SHA256 $alert.SHA256 -DurationHours $config.action_policies.network_block_duration_hours
        }
    }

    Save-PendingAlerts -Alerts $remaining
}

function Start-SentinelLoop {
    $script:DecisionTimer = New-Object System.Windows.Forms.Timer
    $script:DecisionTimer.Interval = 5000
    $script:DecisionTimer.Add_Tick({ Process-PendingDecisions })
    $script:DecisionTimer.Start()

    while ($script:Running) {
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 500

        if (-not (Get-EventSubscriber -SourceIdentifier "Sentinel.ProcessStart" -ErrorAction SilentlyContinue)) {
            if ($script:Running) { Start-SentinelWatchers }
        }
    }
}

function Stop-Sentinel {
    $script:Running = $false
    Stop-SentinelWatchers
    Stop-TrayIcon
    if ($script:DecisionTimer) { $script:DecisionTimer.Stop(); $script:DecisionTimer.Dispose() }
    Write-SentinelLog "Sentinela Defender stopped."
}

function Initialize-Sentinel {
    Write-SentinelLog "========================================"
    Write-SentinelLog "Sentinela Defender v1.0.0 starting..."
    Write-SentinelLog "========================================"

    Initialize-SentinelDirs

    Upgrade-SentinelConfig

    Start-SentinelWatchers

    $config = Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-SentinelLog "Mode: $($config.mode)"

    $dashboardAction = {
        Show-Dashboard
    }

    $exitAction = {
        Stop-Sentinel
    }

    if (-not $NoTray) {
        Initialize-TrayIcon -DashboardCallback $dashboardAction -ExitCallback $exitAction
    }

    if ($Dashboard) {
        Show-Dashboard
    }

    Write-SentinelLog "Sentinela Defender ready."
    Write-SentinelLog "Tray icon active. Left-click to open Dashboard."

    Start-SentinelLoop
}

function Upgrade-SentinelConfig {
    $configPath = "$script:SentinelDir\sentinel-config.json"
    $config = Get-Content $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $changed = $false

    if (-not $config.PSObject.Properties.Name -contains "version") {
        $config | Add-Member -MemberType NoteProperty -Name "version" -Value "1.0.0"
        $changed = $true
    }

    if (-not $config.PSObject.Properties.Name -contains "dev_mode") {
        $devMode = [PSCustomObject]@{
            enabled = $true
            project_directories = @("C:\Users\AKALM\Documents", "C:\Users\AKALM\source", "C:\Users\AKALM\repos")
            ignore_absence_of_signature = $true
            ignore_recent_creation = $true
            ignore_user_dir_location = $true
        }
        $config | Add-Member -MemberType NoteProperty -Name "dev_mode" -Value $devMode
        $changed = $true
    }

    if ($changed) {
        $config | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
        Write-SentinelLog "Config upgraded to latest version."
    }
}

try {
    Initialize-Sentinel
} catch {
    Write-SentinelLog "Fatal error: $_" -Level "ERROR"
    Write-SentinelLog $_.ScriptStackTrace -Level "ERROR"
} finally {
    Stop-Sentinel
}
