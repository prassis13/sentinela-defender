param([switch]$Quick)

$ErrorActionPreference = "Stop"
$script:BaseDir = "C:\Users\AKALM\seguranca"
$script:SentinelDir = "$script:BaseDir\sentinel"
$script:ModuleDir = "$script:SentinelDir\modules"
$script:TestDir = "$script:BaseDir\test"
$script:EvidenceDir = "$script:TestDir\evidence"
if (-not (Test-Path $script:EvidenceDir)) { New-Item -ItemType Directory -Path $script:EvidenceDir -Force | Out-Null }

$logFile = "$script:TestDir\test-report.log"
function Write-TestLog { param([string]$M) $t = Get-Date -Format "HH:mm:ss"; $line = "[$t] $M"; Add-Content -Path $logFile -Value $line -Encoding UTF8; Write-Host $line }

Write-TestLog "============================================"
Write-TestLog "SENTINELA DEFENDER - TEST SUITE v1.0.0"
Write-TestLog "============================================"

# Load all modules
Write-TestLog "Loading modules..."
. "$script:ModuleDir\sentinel-utils.ps1"
. "$script:ModuleDir\risk-engine.ps1"
. "$script:ModuleDir\rule-engine.ps1"
Write-TestLog "Core modules loaded."

# Test 1: Configuration integrity
Write-TestLog "--- Test 1: Configuration integrity ---"
$config = Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
if ($config.version -eq "1.0.0") { Write-TestLog "PASS: Config version 1.0.0" } else { Write-TestLog "FAIL: Config version mismatch" }
if ($config.mode -eq "learn") { Write-TestLog "PASS: Mode is learn" } else { Write-TestLog "FAIL: Mode is not learn" }
if ($config.risk_weights.signed_microsoft -eq 40) { Write-TestLog "PASS: Risk weights loaded" } else { Write-TestLog "FAIL: Risk weights mismatch" }

# Test 2: Utility functions
Write-TestLog "--- Test 2: Utility functions ---"
$ts = Get-SentinelTimestamp
if ($ts) { Write-TestLog "PASS: Get-SentinelTimestamp = $ts" } else { Write-TestLog "FAIL: Get-SentinelTimestamp" }

$tsf = Get-SentinelTimestampFile
if ($tsf) { Write-TestLog "PASS: Get-SentinelTimestampFile = $tsf" } else { Write-TestLog "FAIL: Get-SentinelTimestampFile" }

# Test 3: Risk engine
Write-TestLog "--- Test 3: Risk engine ---"
$riskLevels = @(-60, -30, 0, 30, 60)
$expectedLevels = @("critical", "high_risk", "caution", "known", "safe")
for ($i = 0; $i -lt $riskLevels.Length; $i++) {
    $level = Get-RiskLevel -Score $riskLevels[$i]
    if ($level -eq $expectedLevels[$i]) { Write-TestLog "PASS: Score $($riskLevels[$i]) -> $level" } else { Write-TestLog "FAIL: Score $($riskLevels[$i]) expected $($expectedLevels[$i]) got $level" }
}

$color = Get-RiskColor -Level "critical"
if ($color -eq "#ff4444") { Write-TestLog "PASS: Get-RiskColor" } else { Write-TestLog "FAIL: Get-RiskColor" }

$icon = Get-RiskIcon -Level "critical"
if ($icon) { Write-TestLog "PASS: Get-RiskIcon = $icon" } else { Write-TestLog "FAIL: Get-RiskIcon" }

# Test 4: Protection list
Write-TestLog "--- Test 4: Protection list ---"
$protTests = @(
    @{Name="svchost"; Path="C:\Windows\System32\svchost.exe"; Publisher="Microsoft Corporation"; Expected=$true},
    @{Name="chrome"; Path="C:\Program Files\Google\Chrome\chrome.exe"; Publisher="Google LLC"; Expected=$true},
    @{Name="whatsapp.root"; Path="C:\Program Files\WindowsApps\WhatsApp\whatsapp.exe"; Publisher="WhatsApp Inc."; Expected=$true},
    @{Name="node"; Path="C:\Users\AKALM\AppData\Roaming\npm\node.exe"; Publisher=$null; Expected=$true},
    @{Name="unknown.exe"; Path="C:\Users\AKALM\AppData\Local\Temp\unknown.exe"; Publisher=$null; Expected=$false}
)
foreach ($t in $protTests) {
    $result = Test-IsInProtectionList -ProcessName $t.Name -Path $t.Path -Publisher $t.Publisher
    if ($result -eq $t.Expected) { Write-TestLog "PASS: Protection $($t.Name) = $result" } else { Write-TestLog "FAIL: Protection $($t.Name) expected $($t.Expected) got $result" }
}

# Test 5: Dev mode
Write-TestLog "--- Test 5: Dev mode ---"
$devResult = Test-IsDevModePath -Path "C:\Users\AKALM\Documents\myproject\test.exe"
if ($devResult) { Write-TestLog "PASS: Dev mode path detected" } else { Write-TestLog "FAIL: Dev mode path not detected" }

$devResult2 = Test-IsDevModePath -Path "C:\Windows\System32\cmd.exe"
if (-not $devResult2) { Write-TestLog "PASS: System path not in dev mode" } else { Write-TestLog "FAIL: System path incorrectly in dev mode" }

# Test 6: Rule engine (without touching firewall)
Write-TestLog "--- Test 6: Rule engine ---"
$rules = Get-AllRules
Write-TestLog "Current rules: $($rules.Count)"

# Test 7: Risk classification for known processes
Write-TestLog "--- Test 7: Real process classification ---"
$currentPid = $pid
$testProcessNames = @("powershell", "explorer")
$testPids = @($currentPid)
$anyProcess = $false

foreach ($pname in $testProcessNames) {
    try {
        $proc = Get-Process -Name $pname -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc) { $testPids += $proc.Id }
    } catch {}
}

foreach ($p in ($testPids | Select-Object -Unique)) {
    try {
        $details = Get-ProcessDetails -ProcessId $p
        if ($details) {
            $anyProcess = $true
            $classified = Classify-Risk -ProcessId $details.ProcessId -ProcessName $details.ProcessName -Path $details.Path -SHA256 $details.SHA256 -Publisher $details.Company -CommandLine $details.CommandLine
            Write-TestLog "Process: $($details.ProcessName) ($($details.ProcessId))"
            Write-TestLog "  Path: $($details.Path)"
            Write-TestLog "  Publisher: $($details.Company)"
            Write-TestLog "  Signature: $($details.Signature.Status)"
            Write-TestLog "  Score: $($classified.Score)"
            Write-TestLog "  Level: $($classified.Level)"
        } else { Write-TestLog "No details for PID $pid - path not accessible" }
    } catch { $errMsg = $_.Exception.Message; Write-TestLog "Could not test PID $pid : $errMsg" }
}
if (-not $anyProcess) { Write-TestLog "WARN: No test processes could be classified" }

# Test 8: Whitelist
Write-TestLog "--- Test 8: Whitelist ---"
$whitelist = Read-Whitelist
Write-TestLog "Whitelist entries: $($whitelist.Count)"

# Test 9: Alert system
Write-TestLog "--- Test 9: Alert system ---"
$testAlert = Add-Alert -ProcessName "test.exe" -Path "C:\test\test.exe" -SHA256 "aabbcc" -RiskLevel "caution" -Score -10 -Summary "Test alert" -ProcessId 9999
$alerts = Get-AlertHistory
Write-TestLog "Alert history count: $($alerts.Count)"
if ($alerts.Count -gt 0) { Write-TestLog "PASS: Alert system working" } else { Write-TestLog "FAIL: No alerts found" }

# Test 10: Pending alerts
Write-TestLog "--- Test 10: Pending alerts ---"
$pendingAlert = [PSCustomObject]@{
    Timestamp = Get-SentinelTimestamp
    ProcessName = "test-pending.exe"
    Path = "C:\test\test-pending.exe"
    RiskLevel = "high_risk"
    Score = -30
    Summary = "Test pending alert"
    PID = 8888
    ID = [guid]::NewGuid().ToString().Substring(0, 8)
}
Add-PendingAlert -Alert $pendingAlert
$pending = Get-PendingAlerts
Write-TestLog "Pending alerts: $($pending.Count)"
Clear-PendingAlerts
$cleared = Get-PendingAlerts
Write-TestLog "After clear: $($cleared.Count) pending"

# Test 11: File hash
Write-TestLog "--- Test 11: File hash ---"
$hash = Get-FileHashSHA256 -Path "C:\Windows\System32\notepad.exe"
if ($hash) { Write-TestLog "PASS: SHA256(notepad.exe) = $($hash.Substring(0, 16))..." } else { Write-TestLog "FAIL: SHA256(notepad.exe)" }

# Test 12: Network connections (read-only)
Write-TestLog "--- Test 12: Network connections ---"
try {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $count = ($connections | Measure-Object).Count
    Write-TestLog "Active connections: $count"
} catch { Write-TestLog "NetTCPConnection not available (non-admin)" }

# Summary
Write-TestLog "============================================"
Write-TestLog "TEST SUITE COMPLETE"
Write-TestLog "Log file: $logFile"
Write-TestLog "============================================"
