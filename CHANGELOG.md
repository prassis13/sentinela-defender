# Changelog

## [v1.0.0] - 2026-06-20

### Adicionado
- Motor de risco (risk-engine.ps1): score -100 a +100 com pesos para assinatura, fabricante, caminho, reputação, comportamento
- Motor de regras (rule-engine.ps1): regras persistentes allow/block com expiração automática + rollback via firewall
- Monitoramento híbrido (sentinel-events.ps1): WMI push para processos + polling para conexões, registro e tarefas agendadas
- Ícone na bandeja do Windows (sentinel-tray.ps1): NotifyIcon com menu de contexto, balões de alerta, alternância de modo
- Dashboard WinForms (sentinel-dashboard.ps1): grid de alertas, conexões ativas, decisões pendentes, auto-refresh 3s
- Ponto de entrada principal (sentinel.ps1): carregamento de módulos, loop de decisões, watchdog de watchers
- Modo desenvolvedor: não penaliza projetos em Documents/source/repos
- Modo aprendizado (7 dias): observa sem bloquear, constrói reputação
- Modo proteção: bloqueio de rede para nível crítico com expiração configurável
- Proteção total para Windows, navegadores, WhatsApp, Docker, LM Studio, OpenCode, Node.js, Python, WSL
- CI via GitHub Actions (esqueletos)

### Alterado
- README.md: documentação completa do projeto, arquitetura, casos de uso, públicos
- .gitignore: exclusão de backup, secrets, artefatos pré-existentes
- Configuração central atualizada para v1.0.0 com dev_mode e monitoring flags
- ROADMAP.md e CHANGELOG.md atualizados

### Segurança
- Nenhuma exclusão automática de arquivos ou programas
- Bloqueio só com confirmação do usuário (exceto critical em modo protect, que bloqueia rede temporariamente)
- Regras de firewall com prefixo `Sentinel_Block_` para rollback seguro

## [v0.1-alpha] - 2026-06-19

### Adicionado
- Inventário completo de componentes existentes
- Backup do sistema original
- Estrutura de diretórios do Sentinela Defender
- Configuração central (sentinel-config.json)
- Módulo de utilitários compartilhados (sentinel-utils.ps1)
- .gitignore e configuração Git
- Documentação inicial do projeto
