$ErrorActionPreference = "Continue"
$dataHora = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$dataCurta = Get-Date -Format "dd/MM HH:mm"
$baseDir = "C:\Users\AKALM\seguranca"
$logDir = "$baseDir\log"
$whitelistFile = "$baseDir\whitelist.txt"
$logFile = "$logDir\auditoria.log"
$relatorioHtml = "$baseDir\relatorio.html"

if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

$whitelist = @()
if (Test-Path $whitelistFile) {
    Get-Content $whitelistFile | ForEach-Object {
        $linha = $_.Trim().ToLower()
        if ($linha -ne "" -and -not $linha.StartsWith("#")) {
            $whitelist += ($linha -replace '\.exe$', '')
        }
    }
}

# Conexoes
$conexoes = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object {
        $_.RemoteAddress -notlike '127.*' -and
        $_.RemoteAddress -notlike '192.168.*' -and
        $_.RemoteAddress -notlike '10.*' -and
        ($_.RemoteAddress -notlike '172.1[6-9].*') -and
        ($_.RemoteAddress -notlike '172.2[0-9].*') -and
        ($_.RemoteAddress -notlike '172.3[0-1].*') -and
        ($_.RemoteAddress -ne '::1') -and
        ($_.RemoteAddress -notlike 'fe80::*')
    } |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($proc) {
            [PSCustomObject]@{
                PID       = $_.OwningProcess
                Processo  = $proc.ProcessName
                Path      = $proc.Path
                Empresa   = $proc.Company
                Remoto    = $_.RemoteAddress
                Porta     = $_.RemotePort
            }
        }
    }

$conexoesUnicas = $conexoes | Sort-Object Processo, Porta -Unique

$confiaveis = @()
$desconhecidos = @()
foreach ($c in $conexoesUnicas) {
    $procLower = ($c.Processo.ToLower()) -replace '\.exe$', ''
    if ($whitelist -contains $procLower) {
        $confiaveis += $c
    } else {
        $desconhecidos += $c
    }
}

# Log
$logEntry = @"
[$dataHora] Conexoes: $($conexoesUnicas.Count) | OK: $($confiaveis.Count) | Novos: $($desconhecidos.Count)
"@
Add-Content -Path $logFile -Value $logEntry -Encoding UTF8

# Funcao para gerar linha de tabela
function Gerar-Linha($item, $ehNovo) {
    $cor = if ($ehNovo) { "#ffcccc" } else { "#e0e0e0" }
    $empresa = if ($item.Empresa) { "<span class='empresa'>$($item.Empresa)</span>" } else { "" }
    $status = if ($ehNovo) { "<span class='novo'>DESCONHECIDO</span>" } else { "<span class='ok'>CONHECIDO</span>" }
    return "<tr><td>$status</td><td><b>$($item.Processo)</b><br>$empresa</td><td class='path'>$($item.Path)</td><td>$($item.Remoto)</td><td>$($item.Porta)</td></tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Auditoria de Saida de Rede</title>
<meta http-equiv="refresh" content="60">
<style>
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', Tahoma, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #0e0e0e; color: #e0e0e0; }
h1 { color: #4ec9b0; border-bottom: 2px solid #4ec9b0; padding-bottom: 10px; margin-bottom: 5px; }
.subtitulo { color: #888; font-size: 0.95em; margin-top: 0; }
.resumo { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 25px 0; }
.card { background: linear-gradient(135deg, #2d2d2d, #1f1f1f); padding: 25px; border-radius: 10px; border-left: 5px solid #4ec9b0; }
.card.ok { border-left-color: #6bcf7f; }
.card.alerta { border-left-color: #ff6b6b; background: linear-gradient(135deg, #3a1a1a, #1f1f1f); }
.card .numero { font-size: 3em; font-weight: bold; line-height: 1; }
.card.ok .numero { color: #6bcf7f; }
.card.alerta .numero { color: #ff6b6b; }
.card .label { color: #c0c0c0; font-size: 0.95em; margin-top: 8px; }
.secao { margin: 30px 0; }
.secao h2 { padding: 10px 15px; border-radius: 6px; font-size: 1.3em; }
.secao h2.ok { background: #1a3a1a; color: #6bcf7f; border-left: 4px solid #6bcf7f; }
.secao h2.alerta { background: #3a1a1a; color: #ff6b6b; border-left: 4px solid #ff6b6b; }
table { width: 100%; border-collapse: collapse; margin: 15px 0; background: #1a1a1a; border-radius: 8px; overflow: hidden; }
th { background: #2d2d2d; color: #4ec9b0; padding: 12px; text-align: left; font-size: 0.9em; }
td { padding: 12px; border-bottom: 1px solid #2a2a2a; vertical-align: top; }
tr:hover { background: #252525; }
.path { font-size: 0.8em; color: #888; word-break: break-all; max-width: 400px; }
.empresa { color: #888; font-size: 0.85em; }
.novo { background: #ff6b6b; color: #000; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
.ok { background: #6bcf7f; color: #000; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
.atualizado { background: #2d2d2d; padding: 10px 15px; border-radius: 6px; margin: 10px 0; color: #4ec9b0; }
.legenda { background: #2d2d2d; padding: 15px; border-radius: 6px; margin: 20px 0; font-size: 0.9em; }
.legenda b { color: #4ec9b0; }
.botoes { margin: 20px 0; }
.botao { display: inline-block; padding: 8px 15px; background: #2d2d2d; color: #4ec9b0; text-decoration: none; border-radius: 4px; margin-right: 10px; border: 1px solid #4ec9b0; }
.sem-alerta { background: linear-gradient(135deg, #1a3a1a, #1f1f1f); padding: 30px; border-radius: 10px; text-align: center; border-left: 5px solid #6bcf7f; }
.sem-alerta .icone { font-size: 3em; }
</style>
</head>
<body>
<h1>Auditoria de Saida de Rede</h1>
<p class="subtitulo">Seu PC esta sendo monitorado. Esta pagina mostra o que esta saindo pra internet agora.</p>
<div class="atualizado">Atualizado em: $dataHora &nbsp;|&nbsp; Atualiza sozinho a cada 60 segundos</div>

<div class="resumo">
    <div class="card"><div class="numero">$($conexoesUnicas.Count)</div><div class="label">Total de conexoes externas ativas</div></div>
    <div class="card ok"><div class="numero">$($confiaveis.Count)</div><div class="label">Programas conhecidos e confiaveis</div></div>
    <div class="card $(if($desconhecidos.Count -gt 0){'alerta'}else{'ok'})"><div class="numero">$($desconhecidos.Count)</div><div class="label">Programas nao reconhecidos</div></div>
</div>
"@

if ($desconhecidos.Count -gt 0) {
    $html += "<div class='secao'><h2 class='alerta'>ATENCAO: Programa(s) nao reconhecido(s) encontrado(s)</h2>"
    $html += "<p>Os programas abaixo NAO estao na sua lista de confiaveis. Antes de usar o PC, abra o Hermes e me pergunte se sao legitimos.</p>"
    $html += "<table><tr><th>Status</th><th>Programa</th><th>Caminho</th><th>IP Remoto</th><th>Porta</th></tr>"
    foreach ($d in $desconhecidos) {
        $html += Gerar-Linha $d $true
    }
    $html += "</table></div>"
} else {
    $html += "<div class='sem-alerta'><div class='icone'>OK</div><h2>Tudo certo por agora</h2><p>Nenhum programa desconhecido fez saida pra internet. Pode trabalhar tranquilo.</p></div>"
}

if ($confiaveis.Count -gt 0) {
    $html += "<div class='secao'><h2 class='ok'>Programas confiaveis com conexao ativa</h2>"
    $html += "<p>Estes estao na sua whitelist. Conexao esperada.</p>"
    $html += "<table><tr><th>Status</th><th>Programa</th><th>Caminho</th><th>IP Remoto</th><th>Porta</th></tr>"
    foreach ($c in $confiaveis) {
        $html += Gerar-Linha $c $false
    }
    $html += "</table></div>"
}

$html += @"

<div class="legenda">
    <b>Como ler este relatorio:</b><br>
    - <span class="ok">CONHECIDO</span> = programa que esta na sua whitelist (whitelist.txt). Normal.<br>
    - <span class="novo">DESCONHECIDO</span> = programa que NAO esta na lista. Pode ser legitimo (instalei algo novo) ou pode ser malware. Me pergunte.<br>
    - Atualiza sozinho a cada 60 segundos. <b>Deixa essa pagina aberta no navegador pra ver em tempo real.</b>
</div>

<div class="botoes">
    <a class="botao" href="file:///C:/Users/AKALM/seguranca/auditoria_skills.html">Ver auditoria de skills do Hermes</a>
    <a class="botao" href="file:///C:/Users/AKALM/seguranca/whitelist.txt">Editar whitelist</a>
    <a class="botao" href="file:///C:/Users/AKALM/seguranca/log/auditoria.log">Ver historico do log</a>
</div>

</body></html>
"@

Set-Content -Path $relatorioHtml -Value $html -Encoding UTF8

# Popup so se houver desconhhecido
if ($desconhecidos.Count -gt 0) {
    $titulo = "ATENCAO - Auditoria de Rede"
    $msg = "Existem $($desconhecidos.Count) programa(s) nao reconhecido(s) saindo pra internet:`n`n"
    foreach ($d in $desconhecidos) {
        $msg += "- $($d.Processo) -> $($d.Remoto):$($d.Porta)`n"
    }
    $msg += "`nAbra o relatorio.html para mais detalhes."
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($msg, $titulo, [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
}

Write-Host "OK" -ForegroundColor Green
Write-Host "Conexoes: $($conexoesUnicas.Count) | OK: $($confiaveis.Count) | Novos: $($desconhecidos.Count)"
Write-Host "Relatorio: $relatorioHtml"
