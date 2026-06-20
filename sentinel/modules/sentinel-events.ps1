$script:Watchers = @()
$script:EventHandlers = @{}
$script:Running = $true
$script:KnownRegState = @{}
$script:KnownTasks = @()
$script:KnownConnections = @{}

function Start-ProcessWatcher {
    $query = "SELECT * FROM Win32_ProcessStartTrace"
    $action = {
        $processId = $event.SourceEventArgs.NewEvent.ProcessID
        $processName = $event.SourceEventArgs.NewEvent.ProcessName
        $path = $null
        $cmdLine = $null

        try {
            $proc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
            if ($proc) {
                $path = $proc.ExecutablePath
                $cmdLine = $proc.CommandLine
            }
        } catch {}

        if (-not $path) {
            try {
                $procInfo = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if ($procInfo) { $path = $procInfo.Path }
            } catch {}
        }

        if ($path) {
            $sha256 = Get-FileHashSHA256 -Path $path
            $publisher = (Get-ProcessDetails -PID $processId).Company
            $classified = Classify-Risk -ProcessId $processId -ProcessName $processName -Path $path -SHA256 $sha256 -Publisher $publisher -CommandLine $cmdLine

            if ($classified -and $classified.Level -in @("high_risk", "critical")) {
                $alert = [PSCustomObject]@{
                    Timestamp = Get-SentinelTimestamp
                    ProcessName = $processName
                    Path = $path
                    RiskLevel = $classified.Level
                    Score = $classified.Score
                    Summary = "Process $processName started with risk level $($classified.Level)"
                    PID = $processId
                    ID = [guid]::NewGuid().ToString().Substring(0, 8)
                }
                Add-PendingAlert -Alert $alert
                Add-Alert -ProcessName $processName -Path $path -SHA256 $sha256 -RiskLevel $classified.Level -Score $classified.Score -Summary "Process started: $processName" -PID $processId
            }
        }
    }
    Register-WmiEvent -Query $query -SourceIdentifier "Sentinel.ProcessStart" -Action $action -ErrorAction SilentlyContinue
    $watcher = Get-EventSubscriber -SourceIdentifier "Sentinel.ProcessStart" -ErrorAction SilentlyContinue
    if ($watcher) { $script:Watchers += $watcher }
}

function Start-RegistryStartupWatcher {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $interval = 30
    $timer = New-Object System.Timers.Timer
    $timer.Interval = $interval * 1000

    foreach ($path in $paths) {
        try {
            $converted = $path -replace 'HKLM:', 'HKLM' -replace 'HKCU:', 'HKCU'
            if (Test-Path $path) {
                $script:KnownRegState[$converted] = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            }
        } catch {}
    }

    $timer.Add_Elapsed({
        $currentState = @{}
        foreach ($rp in $paths) {
            try {
                $converted = $rp -replace 'HKLM:', 'HKLM' -replace 'HKCU:', 'HKCU'
                if (Test-Path $rp) {
                    $currentState[$converted] = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
                }
            } catch {}
        }

        foreach ($converted in $currentState.Keys) {
            $old = $script:KnownRegState[$converted]
            $new = $currentState[$converted]
            if ($old -and $new) {
                $oldKeys = $old.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") } | ForEach-Object { $_.Name }
                $newKeys = $new.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") } | ForEach-Object { $_.Name }
                $added = $newKeys | Where-Object { $_ -notin $oldKeys }
                foreach ($key in $added) {
                    $alert = [PSCustomObject]@{
                        Timestamp = Get-SentinelTimestamp
                        ProcessName = $key
                        Path = "$converted\$key"
                        RiskLevel = "high_risk"
                        Score = -30
                        Summary = "New startup entry: $key = $($new.$key)"
                        PID = 0
                        ID = [guid]::NewGuid().ToString().Substring(0, 8)
                    }
                    Add-PendingAlert -Alert $alert
                    Add-Alert -ProcessName $key -Path "$converted\$key" -SHA256 $null -RiskLevel "high_risk" -Score -30 -Summary "New startup entry: $key" -PID 0
                }
            }
        }
        $script:KnownRegState = $currentState
    })

    $timer.AutoReset = $true
    $timer.Start()
    $script:EventHandlers["RegistryTimer"] = $timer
}

function Start-TaskWatcher {
    $interval = 60
    $timer = New-Object System.Timers.Timer
    $timer.Interval = $interval * 1000

    $script:KnownTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object State -ne "Disabled" | ForEach-Object { $_.TaskName })

    $timer.Add_Elapsed({
        $currentTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object State -ne "Disabled" | ForEach-Object { $_.TaskName })
        $newTasks = $currentTasks | Where-Object { $_ -notin $script:KnownTasks }
        foreach ($taskName in $newTasks) {
            $alert = [PSCustomObject]@{
                Timestamp = Get-SentinelTimestamp
                ProcessName = $taskName
                Path = "TaskScheduler"
                RiskLevel = "high_risk"
                Score = -25
                Summary = "New scheduled task created: $taskName"
                PID = 0
                ID = [guid]::NewGuid().ToString().Substring(0, 8)
            }
            Add-PendingAlert -Alert $alert
            Add-Alert -ProcessName $taskName -Path "TaskScheduler" -SHA256 $null -RiskLevel "high_risk" -Score -25 -Summary "New task: $taskName" -PID 0
        }
        $script:KnownTasks = $currentTasks
    })

    $timer.AutoReset = $true
    $timer.Start()
    $script:EventHandlers["TaskTimer"] = $timer
}

function Start-ConnectionWatcher {
    $interval = 5
    $timer = New-Object System.Timers.Timer
    $timer.Interval = $interval * 1000

    $timer.Add_Elapsed({
        try {
            $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
            $currentKeys = @{}
            foreach ($conn in $connections) {
                $key = "$($conn.OwningProcess):$($conn.RemoteAddress):$($conn.RemotePort)"
                $currentKeys[$key] = $true
                if (-not $script:KnownConnections.ContainsKey($key)) {
                    $procDetails = Get-ProcessDetails -PID $conn.OwningProcess
                    if ($procDetails) {
                        $classified = Classify-Risk -ProcessId $procDetails.ProcessId -ProcessName $procDetails.ProcessName -Path $procDetails.Path -SHA256 $procDetails.SHA256 -Publisher $procDetails.Company -RemoteAddress $conn.RemoteAddress -RemotePort $conn.RemotePort -CommandLine $procDetails.CommandLine
                        if ($classified -and $classified.Level -eq "critical") {
                            $alert = [PSCustomObject]@{
                                Timestamp = Get-SentinelTimestamp
                                ProcessName = $procDetails.ProcessName
                                Path = $procDetails.Path
                                RiskLevel = $classified.Level
                                Score = $classified.Score
                                Summary = "Critical connection: $($procDetails.ProcessName) -> $($conn.RemoteAddress):$($conn.RemotePort)"
                                RemoteAddress = $conn.RemoteAddress
                                RemotePort = $conn.RemotePort
                                PID = $conn.OwningProcess
                                ID = [guid]::NewGuid().ToString().Substring(0, 8)
                            }
                            Add-PendingAlert -Alert $alert
                            Add-Alert -ProcessName $procDetails.ProcessName -Path $procDetails.Path -SHA256 $procDetails.SHA256 -RiskLevel $classified.Level -Score $classified.Score -Summary "New connection: $($conn.RemoteAddress):$($conn.RemotePort)" -RemoteAddress $conn.RemoteAddress -RemotePort $conn.RemotePort -PID $conn.OwningProcess
                        }
                    }
                }
            }
            $script:KnownConnections = $currentKeys
        } catch {}
    })

    $timer.AutoReset = $true
    $timer.Start()
    $script:EventHandlers["ConnectionTimer"] = $timer
}

function Start-SentinelWatchers {
    Write-SentinelLog "Starting WMI and polling watchers..."

    if ((Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json).monitoring.watch_new_processes) {
        Start-ProcessWatcher
    }

    if ((Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json).monitoring.watch_registry_startup) {
        Start-RegistryStartupWatcher
    }

    if ((Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json).monitoring.watch_new_tasks) {
        Start-TaskWatcher
    }

    if ((Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json).monitoring.watch_new_connections) {
        Start-ConnectionWatcher
    }

    Write-SentinelLog "All watchers started."
}

function Stop-SentinelWatchers {
    Write-SentinelLog "Stopping all watchers..."
    $script:Running = $false

    Get-EventSubscriber -SourceIdentifier "Sentinel.ProcessStart" -ErrorAction SilentlyContinue | Unregister-Event -Force -ErrorAction SilentlyContinue

    foreach ($key in $script:EventHandlers.Keys) {
        try {
            $script:EventHandlers[$key].Stop()
            $script:EventHandlers[$key].Dispose()
        } catch {}
    }
    $script:EventHandlers.Clear()
    $script:Watchers.Clear()
    Write-SentinelLog "All watchers stopped."
}

function Get-PendingDecisions {
    $pending = Get-PendingAlerts
    $config = Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $mode = $config.mode

    $decisions = @()
    foreach ($alert in $pending) {
        $decision = [PSCustomObject]@{
            Alert = $alert
            Mode = $mode
            AutoAction = if ($mode -eq "protect" -and $alert.RiskLevel -eq "critical") { "block_network" } else { "notify" }
        }
        $decisions += $decision
    }

    return $decisions
}
