Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms.DataVisualization

$script:DashboardForm = $null
$script:DashboardTimer = $null
$script:RefreshInterval = 3000

function New-RichTextBox {
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.ReadOnly = $true
    $rtb.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $rtb.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
    $rtb.BorderStyle = "None"
    $rtb.Font = New-Object System.Drawing.Font("Cascadia Code", 9)
    return $rtb
}

function New-StatusLabel {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.AutoSize = $true
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    return $lbl
}

function Get-AlertColor {
    param([string]$Level)
    switch ($Level) {
        "critical" { return [System.Drawing.Color]::FromArgb(255, 68, 68) }
        "high_risk" { return [System.Drawing.Color]::FromArgb(255, 140, 0) }
        "caution" { return [System.Drawing.Color]::FromArgb(255, 215, 0) }
        "known" { return [System.Drawing.Color]::FromArgb(107, 207, 127) }
        "safe" { return [System.Drawing.Color]::FromArgb(78, 201, 176) }
        default { return [System.Drawing.Color]::FromArgb(136, 136, 136) }
    }
}

function Initialize-Dashboard {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Sentinela Defender - Dashboard"
    $form.Size = New-Object System.Drawing.Size(900, 600)
    $form.MinimumSize = New-Object System.Drawing.Size(800, 500)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
    $form.ForeColor = [System.Drawing.Color]::White
    $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -Id $pid).Path)

    $topPanel = New-Object System.Windows.Forms.Panel
    $topPanel.Dock = "Top"
    $topPanel.Height = 80
    $topPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $topPanel.Padding = New-Object System.Windows.Forms.Padding(10)

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = "Sentinela Defender v1.0.0"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $lblTitle.Location = New-Object System.Drawing.Point(10, 10)
    $lblTitle.Size = New-Object System.Drawing.Size(300, 30)
    $topPanel.Controls.Add($lblTitle)

    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Text = "Status: Ativo"
    $lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lblStatus.Location = New-Object System.Drawing.Point(10, 45)
    $lblStatus.Size = New-Object System.Drawing.Size(200, 20)
    $topPanel.Controls.Add($lblStatus)

    $lblMode = New-Object System.Windows.Forms.Label
    $lblMode.Text = "Modo: Aprendizado"
    $lblMode.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lblMode.Location = New-Object System.Drawing.Point(250, 45)
    $lblMode.Size = New-Object System.Drawing.Size(200, 20)
    $topPanel.Controls.Add($lblMode)

    $lblStats = New-Object System.Windows.Forms.Label
    $lblStats.Text = "Alertas: 0 | Conexões: 0"
    $lblStats.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lblStats.Location = New-Object System.Drawing.Point(500, 45)
    $lblStats.Size = New-Object System.Drawing.Size(250, 20)
    $topPanel.Controls.Add($lblStats)

    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Text = "Atualizar"
    $btnRefresh.Location = New-Object System.Drawing.Point(770, 10)
    $btnRefresh.Size = New-Object System.Drawing.Size(60, 25)
    $btnRefresh.BackColor = [System.Drawing.Color]::FromArgb(78, 201, 176)
    $btnRefresh.FlatStyle = "Flat"
    $btnRefresh.Add_Click({ Update-DashboardData })
    $topPanel.Controls.Add($btnRefresh)

    $btnFechar = New-Object System.Windows.Forms.Button
    $btnFechar.Text = "Fechar"
    $btnFechar.Location = New-Object System.Drawing.Point(770, 42)
    $btnFechar.Size = New-Object System.Drawing.Size(60, 25)
    $btnFechar.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
    $btnFechar.FlatStyle = "Flat"
    $btnFechar.ForeColor = [System.Drawing.Color]::White
    $btnFechar.Add_Click({ $script:DashboardForm.Hide() })
    $topPanel.Controls.Add($btnFechar)

    $form.Controls.Add($topPanel)

    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Dock = "Fill"
    $tabControl.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    $tabAlerts = New-Object System.Windows.Forms.TabPage
    $tabAlerts.Text = "Alertas Recentes"
    $tabAlerts.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)

    $alertsGrid = New-Object System.Windows.Forms.DataGridView
    $alertsGrid.Dock = "Fill"
    $alertsGrid.BackgroundColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $alertsGrid.ForeColor = [System.Drawing.Color]::White
    $alertsGrid.GridColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $alertsGrid.BorderStyle = "None"
    $alertsGrid.RowHeadersVisible = $false
    $alertsGrid.AllowUserToAddRows = $false
    $alertsGrid.AllowUserToDeleteRows = $false
    $alertsGrid.ReadOnly = $true
    $alertsGrid.AutoSizeColumnsMode = "Fill"
    $alertsGrid.SelectionMode = "FullRowSelect"
    $alertsGrid.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $alertsGrid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $alertsGrid.RowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
    $alertsGrid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
    $alertsGrid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(78, 201, 176)
    $alertsGrid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::Black
    $alertsGrid.Columns.Add("Timestamp", "Data/Hora")
    $alertsGrid.Columns.Add("Level", "Nível")
    $alertsGrid.Columns.Add("Process", "Processo")
    $alertsGrid.Columns.Add("Summary", "Resumo")
    $alertsGrid.Columns.Add("Score", "Score")
    $tabAlerts.Controls.Add($alertsGrid)
    $tabControl.Controls.Add($tabAlerts)

    $tabConnections = New-Object System.Windows.Forms.TabPage
    $tabConnections.Text = "Conexões Ativas"
    $tabConnections.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)

    $connGrid = New-Object System.Windows.Forms.DataGridView
    $connGrid.Dock = "Fill"
    $connGrid.BackgroundColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $connGrid.ForeColor = [System.Drawing.Color]::White
    $connGrid.GridColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $connGrid.BorderStyle = "None"
    $connGrid.RowHeadersVisible = $false
    $connGrid.AllowUserToAddRows = $false
    $connGrid.AllowUserToDeleteRows = $false
    $connGrid.ReadOnly = $true
    $connGrid.AutoSizeColumnsMode = "Fill"
    $connGrid.SelectionMode = "FullRowSelect"
    $connGrid.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $connGrid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $connGrid.RowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
    $connGrid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
    $connGrid.Columns.Add("Process", "Processo")
    $connGrid.Columns.Add("PID", "PID")
    $connGrid.Columns.Add("Remote", "Remoto")
    $connGrid.Columns.Add("Port", "Porta")
    $connGrid.Columns.Add("State", "Estado")
    $tabConnections.Controls.Add($connGrid)
    $tabControl.Controls.Add($tabConnections)

    $tabDecisions = New-Object System.Windows.Forms.TabPage
    $tabDecisions.Text = "Decisões Pendentes"
    $tabDecisions.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)

    $pendingGrid = New-Object System.Windows.Forms.DataGridView
    $pendingGrid.Dock = "Fill"
    $pendingGrid.BackgroundColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $pendingGrid.ForeColor = [System.Drawing.Color]::White
    $pendingGrid.GridColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $pendingGrid.BorderStyle = "None"
    $pendingGrid.RowHeadersVisible = $false
    $pendingGrid.AllowUserToAddRows = $false
    $pendingGrid.AllowUserToDeleteRows = $false
    $pendingGrid.ReadOnly = $true
    $pendingGrid.AutoSizeColumnsMode = "Fill"
    $pendingGrid.SelectionMode = "FullRowSelect"
    $pendingGrid.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $pendingGrid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $pendingGrid.RowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
    $pendingGrid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
    $pendingGrid.Columns.Add("Timestamp", "Data/Hora")
    $pendingGrid.Columns.Add("Process", "Processo")
    $pendingGrid.Columns.Add("Level", "Nível")
    $pendingGrid.Columns.Add("Score", "Score")
    $pendingGrid.Columns.Add("Summary", "Resumo")
    $pendingGrid.Columns.Add("Actions", "Ações")
    $tabDecisions.Controls.Add($pendingGrid)
    $tabControl.Controls.Add($tabDecisions)

    $tabAbout = New-Object System.Windows.Forms.TabPage
    $tabAbout.Text = "Sobre"
    $tabAbout.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)

    $aboutBox = New-RichTextBox
    $aboutBox.Dock = "Fill"
    $aboutBox.Text = @"
Sentinela Defender v1.0.0
Sistema de Detecção e Prevenção Baseado em Risco

Status: Ativo
Modo: Aprendizado (7 dias de observação)
Versão do Config: 1.0.0

Monitorando:
- Inicialização de processos
- Conexões de rede
- Alterações no registro (Run/RunOnce)
- Criação de tarefas agendadas

Políticas:
- Sem bloqueio automático de programas desconhecidos
- Sem exclusão de arquivos ou remoção de programas
- Bloqueio de rede apenas em nível Crítico com confirmação
- Modo Proteção ativa bloqueios somente após período de aprendizado

Proteções:
- Windows, navegadores, WhatsApp, Docker,
  LM Studio, OpenCode, Node.js, Python, WSL
- Programas da Microsoft e editores conhecidos
- Diretórios do sistema e Program Files
"@
    $tabAbout.Controls.Add($aboutBox)
    $tabControl.Controls.Add($tabAbout)

    $form.Controls.Add($tabControl)

    $bottomPanel = New-Object System.Windows.Forms.Panel
    $bottomPanel.Dock = "Bottom"
    $bottomPanel.Height = 30
    $bottomPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

    $lblFooter = New-Object System.Windows.Forms.Label
    $lblFooter.Text = "Sentinela Defender - Monitoramento Contínuo | Eventos em tempo real via WMI"
    $lblFooter.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $lblFooter.ForeColor = [System.Drawing.Color]::Gray
    $lblFooter.Location = New-Object System.Drawing.Point(10, 5)
    $lblFooter.Size = New-Object System.Drawing.Size(600, 20)
    $bottomPanel.Controls.Add($lblFooter)

    $form.Controls.Add($bottomPanel)

    $script:DashboardForm = $form
    $script:AlertsGrid = $alertsGrid
    $script:ConnGrid = $connGrid
    $script:PendingGrid = $pendingGrid
    $script:LblStatus = $lblStatus
    $script:LblMode = $lblMode
    $script:LblStats = $lblStats

    return $form
}

function Update-DashboardData {
    if (-not $script:DashboardForm -or -not $script:DashboardForm.Visible) { return }

    try {
        $config = Get-Content "$script:SentinelDir\sentinel-config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:LblMode.Text = "Modo: $(if($config.mode -eq 'learn'){'Aprendizado'}else{'Proteção'})"
    } catch {}

    try {
        $alerts = Get-AlertHistory
        $script:AlertsGrid.Rows.Clear()
        foreach ($alert in $alerts) {
            $idx = $script:AlertsGrid.Rows.Add($alert.Timestamp, $alert.RiskLevel, $alert.ProcessName, $alert.Summary, $alert.Score)
            $levelColor = Get-AlertColor -Level $alert.RiskLevel
            $script:AlertsGrid.Rows[$idx].DefaultCellStyle.ForeColor = $levelColor
        }
        $script:AlertsGrid.FirstDisplayedScrollingRowIndex = 0
    } catch {}

    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object -First 100
        $script:ConnGrid.Rows.Clear()
        foreach ($conn in $connections) {
            try {
                $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            } catch { $procName = "N/A" }
            $script:ConnGrid.Rows.Add($procName, $conn.OwningProcess, $conn.RemoteAddress, $conn.RemotePort, $conn.State)
        }
    } catch {}

    try {
        $pending = Get-PendingAlerts
        $script:PendingGrid.Rows.Clear()
        foreach ($alert in $pending) {
            $script:PendingGrid.Rows.Add($alert.Timestamp, $alert.ProcessName, $alert.RiskLevel, $alert.Score, $alert.Summary, "Pendente")
        }
    } catch {}

    try {
        $alertCount = (Get-AlertHistory).Count
        $connCount = $script:ConnGrid.Rows.Count
        $script:LblStats.Text = "Alertas: $alertCount | Conexões: $connCount"
    } catch {}
}

function Show-Dashboard {
    if (-not $script:DashboardForm) {
        $form = Initialize-Dashboard
    }

    $form = $script:DashboardForm
    $form.Show()
    $form.BringToFront()

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $script:RefreshInterval
    $timer.Add_Tick({ Update-DashboardData })
    $timer.Start()
    $script:DashboardTimer = $timer

    Update-DashboardData

    $form.Add_FormClosing({
        param($sender, $e)
        if ($e.CloseReason -eq "UserClosing") {
            $e.Cancel = $true
            $form.Hide()
        }
    })
}

function Hide-Dashboard {
    if ($script:DashboardForm) {
        $script:DashboardForm.Hide()
    }
}
