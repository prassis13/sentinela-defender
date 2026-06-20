@echo off
title Auditoria de Seguranca
echo.
echo ============================================
echo   AUDITORIA DE SEGURANCA - Verificando...
echo ============================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\AKALM\seguranca\auditar.ps1"
echo.
echo ============================================
echo   Relatorio salvo em:
echo   C:\Users\AKALM\seguranca\relatorio.html
echo ============================================
echo.
echo Abrindo relatorio no navegador...
timeout /t 2 /nobreak >nul
start "" "C:\Users\AKALM\seguranca\relatorio.html"
echo.
pause
