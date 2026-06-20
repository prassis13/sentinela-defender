# Sentinela Defender

Sistema de detecção e prevenção por níveis de risco para Windows.

Monitora processos, conexões de rede, serviços, tarefas agendadas e persistência usando eventos do sistema WMI. Classifica cada evento em 5 níveis de risco e permite ações defensivas controladas sem bloquear programas legítimos.

## Funcionalidades

- **Ícone na bandeja do Windows** — status visual do sistema
- **Monitoramento por eventos** — processos, conexões, serviços, tarefas, persistência
- **Classificação em 5 níveis** — Seguro, Conhecido, Atenção, Alto Risco, Crítico
- **Score de confiança** — baseado em assinatura, fabricante, caminho, reputação, comportamento
- **Modo Aprendizado** — observa sem bloquear por 7 dias
- **Modo Desenvolvedor** — não penaliza código próprio do usuário
- **Whitelist inteligente** — aprende com uso diário
- **Dashboard** — painel de controle com alertas em tempo real
- **Proteção contra bloqueios automáticos** — lista de proteção integrada
- **Backup automático** — antes de qualquer alteração

## Estrutura

```
C:\Users\AKALM\seguranca\
├── sentinel\                    # Sistema Sentinela
│   ├── modules\
│   │   ├── sentinel-utils.ps1       # Utilitários compartilhados
│   │   ├── risk-engine.ps1          # Motor de classificação de risco
│   │   ├── sentinel-events.ps1      # Monitoramento por eventos WMI
│   │   ├── sentinel-dashboard.ps1   # Painel de controle WinForms
│   │   └── sentinel-tray.ps1        # Ícone na bandeja do Windows
│   ├── sentinel-config.json         # Configuração do sistema
│   ├── sentinel.ps1                 # Ponto de entrada principal
│   ├── evidence\                    # Evidências capturadas
│   ├── backup\                      # Backups automáticos
│   └── data\                        # Dados de reputação e alertas
├── auditar.ps1                  # Script original (mantido como fallback)
├── whitelist.txt                # Whitelist estendida
├── instalar_tarefa.ps1          # Instalador da tarefa horária
├── consultar.bat                # Execução manual
├── relatorio.html               # Dashboard HTML (mantido)
└── log\                         # Logs do sistema
```

## Níveis de Risco

| Nível | Score | Ações |
|---|---|---|
| 🟢 Seguro | ≥ 50 | Apenas registrar |
| 🔵 Conhecido | ≥ 20 | Registrar + relatório |
| 🟡 Atenção | ≥ -20 | Registrar + alerta |
| 🟠 Alto Risco | ≥ -50 | Alerta + decisão do usuário |
| 🔴 Crítico | < -50 | Bloqueio de rede + evidências |

## Regra Principal

Programa desconhecido **não** significa malware.
Programa conhecido **não** significa seguro.

Toda classificação considera: assinatura digital, fabricante, caminho, reputação, comportamento, persistência, conexões e histórico.

## Requisitos

- Windows 10 ou 11
- PowerShell 5.1+
- .NET Framework 4.5+ (incluído no Windows)

## Licença

MIT
