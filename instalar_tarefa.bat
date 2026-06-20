@echo off
REM Instala tarefa agendada de auditoria (roda como admin)

schtasks /Create /TN "AuditoriaSeguranca_Hermes" /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\AKALM\seguranca\auditar.ps1" /SC HOURLY /MO 1 /F
schtasks /Create /TN "AuditoriaSeguranca_Hermes_Login" /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\AKALM\seguranca\auditar.ps1" /SC ONLOGON /F
echo.
echo Se aparecer ERRO DE ACESSO, clique direito neste .bat e escolha "Executar como administrador"
pause
