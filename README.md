# Sentinela Defender

**Assistente de Segurança e Monitoramento para Windows**

Versão: **v1.0.0** | Licença: **MIT** | [GitHub](https://github.com/prassis13/sentinela-defender)

---

## O QUE É

O Sentinela Defender é um **assistente de segurança e monitoramento** para Windows que observa, explica, classifica e auxilia decisões sobre processos, conexões de rede, persistência e tarefas agendadas.

Ele **não é um antivírus tradicional**. Não compete com nem substitui Windows Defender, Malwarebytes ou qualquer solução de segurança existente. Ele os **complementa**.

## QUAL PROBLEMA RESOLVE

Usuários avançados — desenvolvedores, criadores, entusiastas de IA e automação — executam dezenas de ferramentas, scripts e binários que antivírus tradicionais tratam como suspeitos simplesmente por serem desconhecidos. O Sentinela Defender resolve isso com:

- **Contexto completo**: não apenas "programa desconhecido", mas de onde veio, quem assinou, que conexões faz, há quanto tempo existe
- **Classificação por score**: -100 a +100 considerando assinatura, fabricante, caminho, reputação, comportamento
- **Modo Aprendizado**: observa por 7 dias antes de sugerir bloqueios
- **Modo Desenvolvedor**: não penaliza código próprio do usuário
- **Decisão nas mãos do usuário**: detecta → classifica → coleta evidências → exibe contexto → usuário decide

## PARA QUEM FOI CRIADO

- Desenvolvedores que compilam e executam código próprio
- Usuários de IA e Vibe Coding que executam ferramentas experimentais
- Power users com dezenas de ferramentas de linha de comando
- Administradores de sistemas que precisam de visibilidade
- Qualquer pessoa que queira entender o que está rodando no Windows

## DIFERENÇA ENTRE SENTINELA DEFENDER E ANTIVÍRUS

| Aspecto | Antivírus Tradicional | Sentinela Defender |
|---------|----------------------|-------------------|
| Abordagem | Bloqueia ou remove | Monitora, explica, auxilia decisão |
| Programas desconhecidos | Trata como ameaça | Investiga contexto |
| Falsos positivos | Comuns em ferramentas de dev | Prioridade máxima: reduzir |
| Modo automático | Bloqueia sem aviso | Só age com confirmação |
| Consumo | 200-500 MB RAM | ~15-20 MB RAM |
| Público | Usuário geral | Usuário avançado/técnico |

## CASOS DE USO REAIS

1. **Desenvolvedor compila um binário**: antivírus deleta na hora. Sentinela mostra "novo executável, sem assinatura, na pasta de projetos → provavelmente você mesmo compilou"
2. **Ferramenta de IA baixa dependências**: scripts npm/pip disparam processos. Sentinela classifica por reputação (já viu antes?) e origem (npm global? temp?)
3. **Programa legítimo se comporta mal**: WhatsApp, Docker, Node.js podem fazer conexões de rede. Sentinela não bloqueia — só alerta se o padrão for anormal
4. **Tarefa agendada suspeita**: Sentinela detecta novas tasks e alerta com contexto completo

## NÍVEIS DE RISCO

| Nível | Score | Cor | Ações |
|-------|-------|-----|-------|
| Seguro | ≥ 50 | 🟢 | Apenas registrar |
| Conhecido | ≥ 20 | 🔵 | Registrar + relatório |
| Atenção | ≥ -20 | 🟡 | Registrar + alerta |
| Alto Risco | ≥ -50 | 🟠 | Alerta + decisão do usuário |
| Crítico | < -50 | 🔴 | Bloqueio de rede + evidências |

## COMO INSTALAR

```powershell
# 1. Clone o repositório
git clone https://github.com/prassis13/sentinela-defender.git
cd sentinela-defender

# 2. (Opcional) Instalar tarefa de auditoria horária (fallback)
.\instalar_tarefa.ps1
```

## COMO EXECUTAR

```powershell
# Execução padrão (tray icon + monitoramento)
powershell -ExecutionPolicy Bypass -File sentinel\sentinel.ps1

# Com dashboard aberto ao iniciar
powershell -ExecutionPolicy Bypass -File sentinel\sentinel.ps1 -Dashboard

# Apenas dashboard (sem tray)
powershell -ExecutionPolicy Bypass -File sentinel\sentinel.ps1 -Dashboard -NoTray
```

## ARQUITETURA

```
C:\Users\AKALM\seguranca\
├── sentinel\                          # Sistema Sentinela
│   ├── modules\
│   │   ├── sentinel-utils.ps1         # SHA256, assinatura, reputação, whitelist
│   │   ├── risk-engine.ps1            # Score -100..+100, classificação por nível
│   │   ├── rule-engine.ps1            # Regras persistentes allow/block + firewall
│   │   ├── sentinel-events.ps1        # WMI ProcessStart + polling registry/tasks/connections
│   │   ├── sentinel-tray.ps1          # NotifyIcon na bandeja, balões, decisões
│   │   └── sentinel-dashboard.ps1     # WinForms: alertas, conexões, pendências
│   ├── sentinel-config.json           # Configuração central (modo learn/protect)
│   ├── sentinel.ps1                   # Ponto de entrada principal
│   ├── data\
│   │   ├── reputation\                # approved_apps.json, known_apps.json
│   │   ├── alerts\                    # alert_history.json
│   │   └── config\                    # blocked_rules.json
│   ├── evidence\                      # Evidências capturadas
│   └── backup\                        # Backups automáticos
├── auditar.ps1                        # Script original (mantido como fallback)
├── whitelist.txt                      # Whitelist estendida
├── instalar_tarefa.ps1                # Instalador da tarefa horária
├── log\                               # sentinel.log, auditoria.log
├── CHANGELOG.md                       # Histórico de versões
├── ROADMAP.md                         # Próximos passos
└── README.md                          # Este arquivo
```

## MONITORAMENTO

| Evento | Tecnologia | Intervalo |
|--------|-----------|-----------|
| Inicialização de processos | WMI push (Win32_ProcessStartTrace) | Tempo real |
| Conexões de rede | Polling (Get-NetTCPConnection) | 5 segundos |
| Registro de inicialização | Polling (RegistryKey) | 30 segundos |
| Tarefas agendadas | Polling (ScheduledTasks) | 60 segundos |

## COMPATIBILIDADE

O Sentinela Defender funciona com **qualquer software legítimo**, atual ou futuro. Não depende de listas fixas. Programas citados na configuração (Windows, Chrome, WhatsApp, Docker, LM Studio, Node.js, Python, etc.) são apenas exemplos.

## REQUISITOS

- Windows 10 ou 11
- PowerShell 5.1+
- .NET Framework 4.5+ (incluído no Windows)

## COMO CONTRIBUIR

1. Faça um fork do repositório
2. Crie uma branch (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -m 'feat: adiciona nova funcionalidade'`)
4. Push (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

## VERSIONAMENTO

Este projeto segue [Semantic Versioning](https://semver.org/):
- v1.0.0 — versão estável inicial
- v0.x — versões alpha/beta anteriores

## LINKS

- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Repositório GitHub](https://github.com/prassis13/sentinela-defender)
