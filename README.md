# Monitor de Mudanças em Sites
WebCoruja — Monitor de Mudanças em
Sites

**Link do site::** https://helenabuery.github.io/desenvolvimento-web-monitor/ 

Protótipo frontend de um sistema que monitora alterações em páginas web,
detecta diffs linha a linha e demonstra práticas reais de segurança como SSRF
guard, bcrypt e JWT.

# Visão geral
WebCoruja permite cadastrar URLs para monitorar, executa verificações periódicas
simuladas e exibe as diferenças de conteúdo entre snapshots em um visualizador de diff
colorido. O projeto foi construído como protótipo educacional para demonstrar as camadas
de uma aplicação real: frontend, lógica de negócio, dados persistidos e segurança.

# Estrutura de arquivos
src/
├── index.html # Estrutura HTML — telas, views, modal, containers
├── style.css # Estilos — variáveis, componentes, animações
└── app.js # Lógica — auth, SSRF guard, diff engine, renders, localStorage

Sem frameworks, sem bundler, sem dependências locais. Para rodar: abra o index.html
diretamente no navegador.

# Como usar
Acesso demo
Ao abrir o arquivo, a tela de login já está pré-preenchida com as credenciais de
demonstração:
email: demo@watchdiff.io

senha: demo1234

A conta demo vem com dois monitores pré-configurados e diffs já gerados para visualização
imediata.
Criar conta própria
Clique na aba criar conta, preencha nome, email e senha (mínimo 8 caracteres). A senha é
processada com bcrypt (salt rounds = 10) antes de ser salva no localStorage.

# Funcionalidades
Dashboard
Painel inicial com quatro métricas em tempo real (total de monitores, mudanças detectadas,
ativos, erros) e um feed de atividade com linha do tempo das últimas ações.
Monitoramentos
Tabela completa com todos os monitores cadastrados. Cada linha exibe nome, URL, status
atual, intervalo de verificação, horário da última checagem e contagem de linhas
adicionadas/removidas. Ações disponíveis por monitor:
● ⟳ — dispara uma verificação manual imediata
● ⏸ / ▶ — pausa ou retoma o monitor
● ✕ — remove o monitor e apaga o snapshot
Adicionar monitor
O formulário de cadastro aceita:

Campo Descrição

Nome Identificador legível para o monitor

URL Endereço HTTPS do site (validado com SSRF guard em tempo

real)

Intervalo 1 minuto, 1 hora, 6 horas ou 24 horas

Seletor
CSS

Opcional — monitorar apenas um elemento específico da página

Email Endereço para alertas (demo não envia email real)

# Diff Viewer
Selecione um monitor no dropdown para visualizar as diferenças entre o snapshot anterior e
o atual. As linhas são exibidas com contexto de ±2 linhas ao redor de cada mudança:
3 <p>This domain is for use in illustrative examples.</p>
- 4 <p>You may use this domain without prior coordination.</p>
+ 4 <p>You may use this domain in examples without prior coordination.</p>
+ 5 <p>Last updated: May 2026</p>
6 <a href="https://www.iana.org/domains/reserved">More information</a>

Segurança
Painel com demonstrações interativas de cada proteção implementada.

# Segurança
SSRF Guard
Bloqueia URLs que apontam para recursos internos da rede antes de qualquer requisição.
Aplicado tanto ao salvar um monitor quanto a cada verificação agendada.
Ranges bloqueados:
10.0.0.0/8 RFC 1918 — rede privada
172.16.0.0/12 RFC 1918 — rede privada
192.168.0.0/16 RFC 1918 — rede privada

127.0.0.0/8 Loopback
169.254.0.0/16 Link-local (inclui endpoint de metadados AWS)
::1 IPv6 loopback
localhost Hostname local
*.internal Domínios internos
*.local Domínios locais

Protocolos não-HTTPS também são rejeitados. Teste no painel de segurança com exemplos
como http://169.254.169.254/latest/meta-data (endpoint de metadados de
cloud) ou http://10.0.0.1/secret.
Autenticação JWT
Login gera um token JWT simulado com estrutura header.payload.signature em
base64. O payload inclui sub (user id), iat (emissão) e exp (expiração em 7 dias). Em
uma implementação real de backend, o token seria gerado com jsonwebtoken e
verificado via middleware em todas as rotas protegidas.
bcrypt
Senhas são processadas com bcrypt (via bcryptjs CDN) antes de serem salvas. Salt
rounds = 10 neste demo (produção recomenda 12). A verificação no login usa
bcrypt.compareSync, nunca comparação direta de strings. Demonstração ao vivo
disponível no painel de segurança.
Rate Limiting
Limite de 10 monitores por usuário (simulado). Em produção: @fastify/rate-limit no
backend com janela por IP e por usuário autenticado.
Sanitização XSS
Todo conteúdo externo renderizado passa pela função esc(), que escapa &, <, > e ".
Previne que HTML malicioso capturado de um site monitorado seja executado no
navegador.

# Arquitetura interna

Estado global
let state = {
user: null, // usuário autenticado
token: null, // JWT
watches: [], // lista de monitores
snapshots: {}, // snapshots indexados por watch id
activity: [], // feed de eventos (cap: 50)
schedulerInterval: null, // referência do setInterval
};

# Fluxo de verificação
addWatch()
└─ validateUrl() ← SSRF guard
└─ salva no estado
└─ scanWatch() ← após 800ms
├─ simula fetch (timeout 1.2s~2s)
├─ simpleHash(newContent)
├─ compara com snapshot anterior
└─ se hash diferente → computeDiff() → marca 'changed'

# Diff engine
Comparação linha a linha (LCS simplificado). Para cada índice até max(oldLines,
newLines):
● linha só no novo → add
● linha só no antigo → del
● linhas iguais → ctx (contexto)
● linhas diferentes → del + add

# Persistência
Dados salvos em localStorage com chaves por usuário:
wd_users → array de usuários registrados (com hash bcrypt)
wd_watches_{userId} → array de monitores do usuário
wd_snaps_{userId} → objeto de snapshots indexado por watch id
wd_activity_{userId} → array de eventos de atividade

# Dependências externas
Lib Versão

Uso Carregamento

bcryptjs 2.4.3 Hash de senha no browser CDN cdnjs

Syne — Fonte display (títulos) Google Fonts

JetBrains
Mono

— Fonte monospace (código,
badges)

Google Fonts

Geist — Fonte sans-serif (corpo) Google Fonts

Sem dependências de build, sem Node.js, sem npm.

# Limitações do protótipo
Este é um protótipo frontend educacional. Em uma implementação de produção seria
necessário:
● Backend real (Node.js + Fastify ou similar) para executar o scraping fora do browser

● Puppeteer rodando server-side para capturar páginas com JavaScript
● PostgreSQL com tabelas users, watches e snapshots (com índices em
watch_id e captured_at)
● Nodemailer ou serviço de email (SendGrid, Resend) para alertas reais
● JWT verificado no servidor com jsonwebtoken, não simulado no cliente
● SSRF guard no backend via resolução DNS antes do fetch (não apenas regex)
● BullMQ + Redis para fila de jobs de scan com retry e dead-letter queue
● HTTPS obrigatório em produção com certificado TLS

# Roadmap sugerido
Fase 1 — MVP funcional Cadastro de URL, primeiro snapshot manual, exibição de diff de
texto, autenticação básica.
Fase 2 — Automação Scheduler com intervalos configuráveis, envio de email ao detectar
mudança, histórico de snapshots com linha do tempo.
Fase 3 — Avançado Suporte a seletores CSS para monitorar elementos específicos, diff
visual lado a lado, gráfico de frequência de mudanças por site, exportação de relatório em
PDF.

# Créditos
Protótipo criado como demonstração das camadas frontend, backend, dados e segurança
de um sistema de monitoramento de sites. Desenvolvido com HTML, CSS e JavaScript
vanilla + bcryptjs.
