Add-Type -AssemblyName System.Windows.Forms

$script:WatchersStarted = $false
$script:Timers = @()

function Start-ProcessWatcher {
    try {
        Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier "Sentinel.ProcessStart" -Action {
            $processId = $event.SourceEventArgs.NewEvent.ProcessID
            $processName = $event.SourceEventArgs.NewEvent.ProcessName
            $path = $null; $cmdLine = $null
            try { $proc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue; if ($proc) { $path = $proc.ExecutablePath; $cmdLine = $proc.CommandLine } } catch {}
            if (-not $path) { try { $p = Get-Process -Id $processId -ErrorAction SilentlyContinue; if ($p) { $path = $p.Path } } catch {} }
            if ($path) {
                $sha256 = Get-FileHashSHA256 -Path $path
                $publisher = (Get-ProcessDetails -ProcessId $processId).Company
                $classified = Classify-Risk -ProcessId $processId -ProcessName $processName -Path $path -SHA256 $sha256 -Publisher $publisher -CommandLine $cmdLine
                if ($classified.Level -in @("high_risk","critical")) {
                    Add-PendingAlert -Alert ([PSCustomObject]@{Timestamp=Get-SentinelTimestamp; ProcessName=$processName; Path=$path; RiskLevel=$classified.Level; Score=$classified.Score; Summary="Process $processName started with risk level $($classified.Level)"; PID=$processId; ID=[guid]::NewGuid().ToString().Substring(0,8)})
                    Add-Alert -ProcessName $processName -Path $path -SHA256 $sha256 -RiskLevel $classified.Level -Score $classified.Score -Summary "Process started: $processName" -ProcessId $processId
                }
            }
        } -ErrorAction Stop
        Write-SentinelLog "WMI process watcher started (push)."
    } catch {
        Write-SentinelLog "WMI push unavailable. Using polling fallback." -Level "WARN"
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 3000
        $known = @{}
        try { Get-Process | ForEach-Object { $known[$_.Id] = $_.ProcessName } } catch {}
        $timer.Add_Tick({
            try {
                $current = Get-Process -ErrorAction SilentlyContinue
                $currentIds = @{}
                foreach ($p in $current) {
                    $currentIds[$p.Id] = $true
                    if (-not $known.ContainsKey($p.Id)) {
                        $path = $p.Path
                        if (-not [string]::IsNullOrEmpty($path) -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                            $sha256 = Get-FileHashSHA256 -Path $path
                            $publisher = $p.Company
                            $classified = Classify-Risk -ProcessId $p.Id -ProcessName $p.ProcessName -Path $path -SHA256 $sha256 -Publisher $publisher
                            Write-SentinelLog "Detected: $($p.ProcessName) (PID $($p.Id), score $($classified.Score), level $($classified.Level))"
                            if ($classified.Level -in @("high_risk","critical")) {
                                Add-PendingAlert -Alert ([PSCustomObject]@{Timestamp=Get-SentinelTimestamp; ProcessName=$p.ProcessName; Path=$path; RiskLevel=$classified.Level; Score=$classified.Score; Summary="New process: $($p.ProcessName) (risk: $($classified.Level))"; PID=$p.Id; ID=[guid]::NewGuid().ToString().Substring(0,8)})
                                Add-Alert -ProcessName $p.ProcessName -Path $path -SHA256 $sha256 -RiskLevel $classified.Level -Score $classified.Score -Summary "New process: $($p.ProcessName)" -ProcessId $p.Id
                            }
                            Update-AppReputation -Name $p.ProcessName -Path $path -SHA256 $sha256 -Publisher $publisher
                        }
                    }
                }
                $known = $currentIds
            } catch {}
        })
        $timer.Start()
        $script:Timers += $timer
        Write-SentinelLog "Process polling watcher started (3s interval)."
    }
}

function Start-RegistryStartupWatcher {
    $paths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce")
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 30000
    $regState = @{}
    foreach ($path in $paths) { try { $c = $path -replace 'HKLM:','HKLM' -replace 'HKCU:','HKCU'; if (Test-Path $path) { $regState[$c] = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue } } catch {} }
    $timer.Add_Tick({
        $currentState = @{}
        foreach ($rp in $paths) { try { $c = $rp -replace 'HKLM:','HKLM' -replace 'HKCU:','HKCU'; if (Test-Path $rp) { $currentState[$c] = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue } } catch {} }
        foreach ($converted in $currentState.Keys) {
            $old = $regState[$converted]; $new = $currentState[$converted]
            if ($old -and $new) {
                $oldKeys = $old.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider") } | ForEach-Object { $_.Name }
                $newKeys = $new.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider") } | ForEach-Object { $_.Name }
                foreach ($key in ($newKeys | Where-Object { $_ -notin $oldKeys })) {
                    Add-PendingAlert -Alert ([PSCustomObject]@{Timestamp=Get-SentinelTimestamp; ProcessName=$key; Path="$converted\$key"; RiskLevel="high_risk"; Score=-30; Summary="New startup entry: $key"; PID=0; ID=[guid]::NewGuid().ToString().Substring(0,8)})
                    Add-Alert -ProcessName $key -Path "$converted\$key" -SHA256 $null -RiskLevel "high_risk" -Score -30 -Summary "New startup entry: $key" -ProcessId 0
                }
            }
        }
        $regState = $currentState
    })
    $timer.Start()
    $script:Timers += $timer
    Write-SentinelLog "Registry watcher started (30s interval)."
}

function Start-TaskWatcher {
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 60000
    $knownTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object State -ne "Disabled" | ForEach-Object { $_.TaskName })
    $timer.Add_Tick({
        $currentTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object State -ne "Disabled" | ForEach-Object { $_.TaskName })
        foreach ($taskName in ($currentTasks | Where-Object { $_ -notin $knownTasks })) {
            Add-PendingAlert -Alert ([PSCustomObject]@{Timestamp=Get-SentinelTimestamp; ProcessName=$taskName; Path="TaskScheduler"; RiskLevel="high_risk"; Score=-25; Summary="New scheduled task: $taskName"; PID=0; ID=[guid]::NewGuid().ToString().Substring(0,8)})
            Add-Alert -ProcessName $taskName -Path "TaskScheduler" -SHA256 $null -RiskLevel "high_risk" -Score -25 -Summary "New task: $taskName" -ProcessId 0
        }
        $knownTasks = $currentTasks
    })
    $timer.Start()
    $script:Timers += $timer
    Write-SentinelLog "Task watcher started (60s interval)."
}

function Start-ConnectionWatcher {
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 5000
    $knownConns = @{}
    $timer.Add_Tick({
        try {
            $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
            $currentKeys = @{}
            foreach ($conn in $connections) {
                $key = "$($conn.OwningProcess):$($conn.RemoteAddress):$($conn.RemotePort)"
                $currentKeys[$key] = $true
                if (-not $knownConns.ContainsKey($key)) {
                    $d = Get-ProcessDetails -ProcessId $conn.OwningProcess
                    if ($d) {
                        $classified = Classify-Risk -ProcessId $d.ProcessId -ProcessName $d.ProcessName -Path $d.Path -SHA256 $d.SHA256 -Publisher $d.Company -RemoteAddress $conn.RemoteAddress -RemotePort $conn.RemotePort
                        if ($classified.Level -eq "critical") {
                            Add-PendingAlert -Alert ([PSCustomObject]@{Timestamp=Get-SentinelTimestamp; ProcessName=$d.ProcessName; Path=$d.Path; RiskLevel=$classified.Level; Score=$classified.Score; Summary="Critical connection: $($d.ProcessName) -> $($conn.RemoteAddress):$($conn.RemotePort)"; RemoteAddress=$conn.RemoteAddress; RemotePort=$conn.RemotePort; PID=$conn.OwningProcess; ID=[guid]::NewGuid().ToString().Substring(0,8)})
                            Add-Alert -ProcessName $d.ProcessName -Path $d.Path -SHA256 $d.SHA256 -RiskLevel $classified.Level -Score $classified.Score -Summary "New connection: $($conn.RemoteAddress):$($conn.RemotePort)" -RemoteAddress $conn.RemoteAddress -RemotePort $conn.RemotePort -ProcessId $conn.OwningProcess
                        }
                    }
                }
            }
            $knownConns = $currentKeys
        } catch {}
    })
    $timer.Start()
    $script:Timers += $timer
    Write-SentinelLog "Connection watcher started (5s interval)."
}

function Start-SentinelWatchers {
    if ($script:WatchersStarted) { return }
    $script:WatchersStarted = $true
    Write-SentinelLog "Starting WMI and polling watchers..."
    $config = Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($config.monitoring.watch_new_processes) { Start-ProcessWatcher }
    if ($config.monitoring.watch_registry_startup) { Start-RegistryStartupWatcher }
    if ($config.monitoring.watch_new_tasks) { Start-TaskWatcher }
    if ($config.monitoring.watch_new_connections) { Start-ConnectionWatcher }
    Write-SentinelLog "All watchers started."
}

function Stop-SentinelWatchers {
    $script:WatchersStarted = $false
    Write-SentinelLog "Stopping all watchers..."
    foreach ($t in $script:Timers) { try { $t.Stop(); $t.Dispose() } catch {} }
    $script:Timers.Clear()
    Get-EventSubscriber -SourceIdentifier "Sentinel.ProcessStart" -ErrorAction SilentlyContinue | Unregister-Event -Force -ErrorAction SilentlyContinue
    Write-SentinelLog "All watchers stopped."
}
