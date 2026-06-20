$timer = New-Object System.Timers.Timer
$timer.Interval = 2000
$action = { Write-Host ("Timer fired at " + (Get-Date -Format 'HH:mm:ss')) }
$timer.Add_Elapsed($action)
$timer.AutoReset = $true
$timer.Start()
Write-Host "Timer started, waiting 7s..."
Start-Sleep 7
$timer.Stop()
$timer.Dispose()
Write-Host "Done"