# Instalar tarefa agendada de auditoria
# Roda a cada 1 hora e tambem no login do usuario

$taskName = "AuditoriaSeguranca_Hermes"
$scriptPath = "C:\Users\AKALM\seguranca\auditar.ps1"

# Remover tarefa se ja existir
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Criar acao
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""

# Trigger 1: no login
$triggerLogin = New-ScheduledTaskTrigger -AtLogOn

# Trigger 2: a cada 1 hora
$triggerHourly = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650)

# Configuracoes: roda com privilegios do usuario, mesmo se nao estiver logado (nao - so quando logado)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

# Registrar
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($triggerLogin, $triggerHourly) -Principal $principal -Settings $settings -Description "Auditoria de saida de rede - roda a cada 1 hora e no login" | Out-Null

Write-Host "Tarefa agendada criada com sucesso." -ForegroundColor Green
Write-Host "Nome: $taskName" -ForegroundColor Cyan
Write-Host "Horario: a cada 1 hora + no login" -ForegroundColor Cyan
Write-Host ""
Write-Host "Para verificar:" -ForegroundColor Yellow
Write-Host "  Get-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
Write-Host ""
Write-Host "Para desinstalar:" -ForegroundColor Yellow
Write-Host "  Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false" -ForegroundColor White
