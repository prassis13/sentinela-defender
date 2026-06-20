Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:TrayIcon = $null
$script:TrayMenu = $null
$script:TrayRunning = $true

function Get-EmbeddedIcon {
    $bmp = New-Object System.Drawing.Bitmap 16, 16
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = "HighQuality"
    $g.Clear([System.Drawing.Color]::FromArgb(0, 0, 0, 0))
    $penGreen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 78, 201, 176), 2)
    $penGray = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 100, 100, 100), 2)
    $g.DrawEllipse($penGreen, 2, 2, 12, 12)
    $g.DrawLine($penGreen, 5, 8, 8, 11)
    $g.DrawLine($penGreen, 8, 11, 12, 5)
    $g.Dispose()
    $icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
    $bmp.Dispose()
    return $icon
}

function Get-EmbeddedIconAlert {
    $bmp = New-Object System.Drawing.Bitmap 16, 16
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = "HighQuality"
    $g.Clear([System.Drawing.Color]::FromArgb(0, 0, 0, 0))
    $penOrange = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 255, 140, 0), 2)
    $g.DrawEllipse($penOrange, 2, 2, 12, 12)
    $g.DrawLine($penOrange, 8, 4, 8, 9)
    $g.DrawLine($penOrange, 8, 11, 8, 12)
    $g.Dispose()
    $icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
    $bmp.Dispose()
    return $icon
}

function Show-BalloonTip {
    param([string]$Title, [string]$Text, [string]$Level = "caution")

    if (-not $script:TrayIcon) { return }
    $icon = switch ($Level) {
        "critical" { [System.Windows.Forms.ToolTipIcon]::Error }
        "high_risk" { [System.Windows.Forms.ToolTipIcon]::Warning }
        default { [System.Windows.Forms.ToolTipIcon]::Info }
    }

    try {
        $script:TrayIcon.ShowBalloonTip(10000, $Title, $Text, $icon)
    } catch {}
}

function Initialize-TrayIcon {
    param([scriptblock]$DashboardCallback, [scriptblock]$ExitCallback)

    $icon = Get-EmbeddedIcon
    $script:TrayIcon = New-Object System.Windows.Forms.NotifyIcon
    $script:TrayIcon.Icon = $icon
    $script:TrayIcon.Text = "Sentinela Defender - Observando"
    $script:TrayIcon.Visible = $true

    $menu = New-Object System.Windows.Forms.ContextMenuStrip

    $statusItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $statusItem.Text = "Sentinela Defender"
    $statusItem.Enabled = $false
    $menu.Items.Add($statusItem)

    $menu.Items.Add("-")

    $dashboardItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $dashboardItem.Text = "Dashboard"
    $dashboardItem.Add_Click({
        if ($DashboardCallback) { & $DashboardCallback }
    })
    $menu.Items.Add($dashboardItem)

    $modeItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $modeItem.Text = "Modo: Aprendizado"
    $modeItem.Add_Click({
        $configPath = "$script:SentinelDir\sentinel-config.json"
        $config = Get-Content $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($config.mode -eq "learn") {
            $config.mode = "protect"
            $text = "Modo: Proteção"
        } else {
            $config.mode = "learn"
            $text = "Modo: Aprendizado"
        }
        $config | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
        $modeItem.Text = $text
        Write-SentinelLog "Mode switched to: $($config.mode)"
        Show-BalloonTip -Title "Sentinela Defender" -Text "Modo alterado para: $($config.mode)" -Level "info"
    })
    $menu.Items.Add($modeItem)

    $menu.Items.Add("-")

    $exitItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $exitItem.Text = "Sair"
    $exitItem.Add_Click({
        $script:TrayRunning = $false
        $script:TrayIcon.Visible = $false
        if ($ExitCallback) { & $ExitCallback }
        [System.Windows.Forms.Application]::Exit()
    })
    $menu.Items.Add($exitItem)

    $script:TrayMenu = $menu
    $script:TrayIcon.ContextMenuStrip = $menu

    $script:TrayIcon.Add_MouseClick({
        param($sender, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
            if ($DashboardCallback) { & $DashboardCallback }
        }
    })
}

function Set-TrayAlert {
    param([bool]$HasAlert)

    if (-not $script:TrayIcon) { return }
    if ($HasAlert) {
        $script:TrayIcon.Icon = Get-EmbeddedIconAlert
        $script:TrayIcon.Text = "Sentinela Defender - ATENÇÃO"
    } else {
        $script:TrayIcon.Icon = Get-EmbeddedIcon
        $config = Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:TrayIcon.Text = "Sentinela Defender - Modo: $($config.mode)"
    }
}

function Show-TrayDecision {
    param(
        [string]$ProcessName,
        [string]$Path,
        [string]$RiskLevel,
        [int]$Score,
        [string]$Summary,
        [scriptblock]$AllowCallback,
        [scriptblock]$BlockCallback,
        [scriptblock]$IgnoreCallback
    )

    $balloonText = "[$RiskLevel] $ProcessName`nScore: $Score`n$Summary"

    Show-BalloonTip -Title "Sentinela Defender - Ação Requerida" -Text $balloonText -Level $RiskLevel

    $decisionForm = New-Object System.Windows.Forms.Form
    $decisionForm.Text = "Sentinela Defender - Decisão Requerida"
    $decisionForm.Size = New-Object System.Drawing.Size(500, 250)
    $decisionForm.StartPosition = "CenterScreen"
    $decisionForm.TopMost = $true
    $decisionForm.FormBorderStyle = "FixedDialog"
    $decisionForm.MaximizeBox = $false
    $decisionForm.MinimizeBox = $false

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Processo: $ProcessName`nCaminho: $Path`nRisco: $RiskLevel (Score: $Score)`n`n$Summary"
    $label.Location = New-Object System.Drawing.Point(12, 12)
    $label.Size = New-Object System.Drawing.Size(480, 120)
    $decisionForm.Controls.Add($label)

    $btnAllow = New-Object System.Windows.Forms.Button
    $btnAllow.Text = "Permitir"
    $btnAllow.Location = New-Object System.Drawing.Point(12, 160)
    $btnAllow.Size = New-Object System.Drawing.Size(100, 40)
    $btnAllow.BackColor = [System.Drawing.Color]::FromArgb(78, 201, 176)
    $btnAllow.Add_Click({
        $decisionForm.Close()
        if ($AllowCallback) { & $AllowCallback }
    })
    $decisionForm.Controls.Add($btnAllow)

    $btnBlock = New-Object System.Windows.Forms.Button
    $btnBlock.Text = "Bloquear"
    $btnBlock.Location = New-Object System.Drawing.Point(130, 160)
    $btnBlock.Size = New-Object System.Drawing.Size(100, 40)
    $btnBlock.BackColor = [System.Drawing.Color]::FromArgb(255, 68, 68)
    $btnBlock.Add_Click({
        $decisionForm.Close()
        if ($BlockCallback) { & $BlockCallback }
    })
    $decisionForm.Controls.Add($btnBlock)

    $btnIgnore = New-Object System.Windows.Forms.Button
    $btnIgnore.Text = "Ignorar"
    $btnIgnore.Location = New-Object System.Drawing.Point(248, 160)
    $btnIgnore.Size = New-Object System.Drawing.Size(100, 40)
    $btnIgnore.Add_Click({
        $decisionForm.Close()
        if ($IgnoreCallback) { & $IgnoreCallback }
    })
    $decisionForm.Controls.Add($btnIgnore)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancelar"
    $btnCancel.Location = New-Object System.Drawing.Point(366, 160)
    $btnCancel.Size = New-Object System.Drawing.Size(100, 40)
    $btnCancel.BackColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
    $btnCancel.ForeColor = [System.Drawing.Color]::White
    $btnCancel.Add_Click({ $decisionForm.Close() })
    $decisionForm.Controls.Add($btnCancel)

    $decisionForm.ShowDialog()
}

function Stop-TrayIcon {
    $script:TrayRunning = $false
    if ($script:TrayIcon) {
        $script:TrayIcon.Visible = $false
        $script:TrayIcon.Dispose()
        $script:TrayIcon = $null
    }
}
