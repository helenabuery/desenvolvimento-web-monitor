/* ============================================================
  WebCoruja — Lógica da Aplicação  |  app.js
  Depende de: bcryptjs (CDN)
============================================================ */


/* ------------------------------------------------------------
  CONSTANTES DE SEGURANÇA — SSRF Guard
  Ranges de IP privados/reservados bloqueados
------------------------------------------------------------ */

const PRIVATE_RANGES = [
    /^10\.\d+\.\d+\.\d+$/,                    // RFC 1918
    /^192\.168\.\d+\.\d+$/,                   // RFC 1918
    /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,   // RFC 1918
    /^127\.\d+\.\d+\.\d+$/,                   // Loopback
    /^169\.254\.\d+\.\d+$/,                   // Link-local (AWS metadata)
    /^0\.0\.0\.0$/,
    /^::1$/,                                  // IPv6 loopback
    /^localhost$/i,
    /^fc[0-9a-f]{2}:/i,                       // IPv6 unique local
  ];
  
  
  /* ------------------------------------------------------------
    CONTEÚDO SIMULADO PARA DEMO
    Simula dois snapshots distintos por URL
  ------------------------------------------------------------ */
  
  const MOCK_CONTENT = {
    'https://example.com': {
      v1: `<!DOCTYPE html>\n<html>\n<head><title>Example Domain</title></head>\n<body>\n<h1>Example Domain</h1>\n<p>This domain is for use in illustrative examples in documents.</p>\n<p>You may use this domain without prior coordination or asking permission.</p>\n<p><a href="https://www.iana.org/domains/reserved">More information...</a></p>\n</body>\n</html>`,
      v2: `<!DOCTYPE html>\n<html>\n<head><title>Example Domain — Updated</title></head>\n<body>\n<h1>Example Domain</h1>\n<p>This domain is for use in illustrative examples in documents.</p>\n<p>You may use this domain in examples without prior coordination.</p>\n<p>Last updated: May 2026</p>\n<p><a href="https://www.iana.org/domains/reserved">More information...</a></p>\n</body>\n</html>`,
    },
    'https://httpbin.org/get': {
      v1: `{\n  "headers": {\n    "Accept": "*/*",\n    "Host": "httpbin.org",\n    "User-Agent": "WatchDiff/1.0"\n  },\n  "origin": "203.0.113.42",\n  "url": "https://httpbin.org/get"\n}`,
      v2: `{\n  "headers": {\n    "Accept": "text/html,application/xhtml+xml",\n    "Host": "httpbin.org",\n    "User-Agent": "WatchDiff/1.0"\n  },\n  "origin": "203.0.113.42",\n  "url": "https://httpbin.org/get"\n}`,
    },
  };
  
  
  /* ------------------------------------------------------------
    ESTADO GLOBAL DA APLICAÇÃO
  ------------------------------------------------------------ */
  
  let state = {
    user: null,              // usuário logado
    token: null,             // JWT simulado
    watches: [],             // lista de monitors
    snapshots: {},           // snapshots por watch id
    activity: [],            // feed de atividade
    schedulerInterval: null, // referência do setInterval
  };
  
  
  /* ============================================================
    AUTH — AUTENTICAÇÃO
  ============================================================ */
  
  /**
   * Gera um JWT simulado com header.payload.signature.
   * Em produção real: usar jsonwebtoken no backend Node.js.
   */
  function generateToken(userId) {
    const header  = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = btoa(JSON.stringify({
      sub: userId,
      iat: Date.now(),
      exp: Date.now() + 7 * 86400000, // 7 dias
    }));
    const sig = btoa(userId + '_watchdiff_secret').replace(/=/g, '');
    return `${header}.${payload}.${sig}`;
  }
  
  /** Alterna entre abas de Login e Registro. */
  function switchAuthTab(tab, el) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    el.classList.add('active');
    document.getElementById('loginForm').style.display    = tab === 'login'    ? '' : 'none';
    document.getElementById('registerForm').style.display = tab === 'register' ? '' : 'none';
  }
  
  /** Inicializa listeners de UI após o DOM estar pronto. */
  document.addEventListener('DOMContentLoaded', () => {
  
    // Indicador de força de senha em tempo real
    const regPass = document.getElementById('regPass');
    if (regPass) {
      regPass.addEventListener('input', function () {
        const v  = this.value;
        const el = document.getElementById('passStrength');
        if (!v) { el.textContent = ''; return; }
  
        let s, c;
        if      (v.length < 6)  { s = '⚠ muito curta'; c = 'var(--red)';   }
        else if (v.length < 10) { s = '◑ média';        c = 'var(--amber)'; }
        else                    { s = '● forte';         c = 'var(--green)'; }
  
        el.textContent = s;
        el.style.color = c;
      });
    }
  
    // Validação de URL em tempo real ao digitar
    const newUrl = document.getElementById('newUrl');
    if (newUrl) {
      newUrl.addEventListener('input', function () {
        const r  = validateUrl(this.value);
        const el = document.getElementById('urlValidation');
        if (!this.value) { el.textContent = ''; return; }
        el.textContent = r.ok ? '✓ URL válida' : '✗ ' + r.reason;
        el.style.color  = r.ok ? 'var(--green)' : 'var(--red)';
      });
    }
  
    // Fechar modal ao clicar no overlay
    document.getElementById('addModal').addEventListener('click', function (e) {
      if (e.target === this) closeModal();
    });
  
    // Fechar modal com Esc
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') closeModal();
    });
  
    // Pré-popular dados demo no localStorage
    initDemoData();
  });
  
  /** Realiza login — valida com bcrypt ou credenciais demo. */
  function doLogin() {
    const email = document.getElementById('loginEmail').value.trim();
    const pass  = document.getElementById('loginPass').value;
  
    if (!email || !pass) { toast('Preencha email e senha', 'warn'); return; }
  
    const users = JSON.parse(localStorage.getItem('wd_users') || '[]');
    let user = users.find(u => u.email === email);
  
    if (!user) {
      // Conta demo hardcoded para facilitar a apresentação
      if (email === 'demo@watchdiff.io' && pass === 'demo1234') {
        user = { id: 'demo', name: 'Demo User', email };
      } else {
        toast('Usuário não encontrado', 'error');
        return;
      }
    } else {
      // Verificação real com bcrypt
      try {
        if (!bcrypt.compareSync(pass, user.hash)) {
          toast('Senha incorreta', 'error');
          return;
        }
      } catch {
        if (pass !== user.hash) { toast('Senha incorreta', 'error'); return; }
      }
    }
  
    // Sucesso: carregar estado do usuário
    state.user      = user;
    state.token     = generateToken(user.id);
    state.watches   = JSON.parse(localStorage.getItem('wd_watches_'  + user.id) || '[]');
    state.snapshots = JSON.parse(localStorage.getItem('wd_snaps_'    + user.id) || '{}');
    state.activity  = JSON.parse(localStorage.getItem('wd_activity_' + user.id) || '[]');
  
    // Atualizar UI
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('appScreen').style.display   = 'flex';
  
    const initials = user.name.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase();
    document.getElementById('userAvatar').textContent = initials;
    document.getElementById('userName').textContent   = user.name;
  
    renderAll();
    toast('Bem-vindo, ' + user.name.split(' ')[0] + '!', 'ok');
    startScheduler();
  }
  
  /** Cria nova conta com hash bcrypt. */
  function doRegister() {
    const name  = document.getElementById('regName').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const pass  = document.getElementById('regPass').value;
  
    if (!name || !email || !pass) { toast('Preencha todos os campos', 'warn'); return; }
    if (pass.length < 8) { toast('Senha muito curta (mínimo 8 chars)', 'warn'); return; }
  
    const users = JSON.parse(localStorage.getItem('wd_users') || '[]');
    if (users.find(u => u.email === email)) { toast('Email já cadastrado', 'error'); return; }
  
    // Hash bcrypt — salt rounds 10 (produção recomenda 12)
    const hash = bcrypt.hashSync(pass, 10);
    const user = { id: 'u_' + Date.now(), name, email, hash };
    users.push(user);
  
    localStorage.setItem('wd_users', JSON.stringify(users));
    toast('Conta criada! Faça login.', 'ok');
  
    document.getElementById('loginEmail').value = email;
    document.getElementById('loginPass').value  = pass;
    switchAuthTab('login', document.querySelectorAll('.tab')[0]);
  }
  
  /** Encerra sessão e limpa estado. */
  function doLogout() {
    clearInterval(state.schedulerInterval);
    state = { user: null, token: null, watches: [], snapshots: {}, activity: [], schedulerInterval: null };
    document.getElementById('appScreen').style.display  = 'none';
    document.getElementById('loginScreen').style.display = 'flex';
  }
  
  
  /* ============================================================
    SEGURANÇA — VALIDAÇÃO DE URL (SSRF Guard)
  ============================================================ */
  
  /**
   * Valida se uma URL é segura para monitorar.
   * Bloqueia: IPs privados, loopback, link-local,
   * protocolos não-HTTPS, domínios .internal/.local.
   *
   * @param   {string} url
   * @returns {{ ok: boolean, reason?: string }}
   */
  function validateUrl(url) {
    if (!url) return { ok: false, reason: 'URL vazia.' };
  
    try {
      const u = new URL(url);
  
      // Apenas HTTPS permitido
      if (!['https:', 'http:'].includes(u.protocol))
        return { ok: false, reason: `Protocolo "${u.protocol}" não permitido. Use https://` };
  
      if (u.protocol === 'http:')
        return { ok: false, reason: 'Apenas HTTPS é aceito por segurança.' };
  
      const host = u.hostname;
  
      // Bloquear IPs privados e localhost (SSRF)
      for (const re of PRIVATE_RANGES) {
        if (re.test(host))
          return { ok: false, reason: `Host privado/local bloqueado por SSRF guard: ${host}` };
      }
  
      // Bloquear domínios internos
      if (host.endsWith('.internal') || host.endsWith('.local'))
        return { ok: false, reason: `Domínio interno bloqueado: ${host}` };
  
      return { ok: true };
  
    } catch {
      return { ok: false, reason: 'URL inválida. Inclua o protocolo (https://).' };
    }
  }
  
  
  /* ============================================================
    NAVEGAÇÃO — VIEWS
  ============================================================ */
  
  /** Exibe uma view e atualiza navegação. */
  function showView(view, el) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  
    document.getElementById('view-' + view).classList.add('active');
    if (el) el.classList.add('active');
  
    const titles = {
      dashboard: 'dashboard',
      watches:   'monitoramentos',
      diffs:     'diff viewer',
      security:  'segurança',
    };
    document.getElementById('viewTitle').textContent = titles[view] || view;
  
    if (view === 'diffs') populateDiffSelect();
  }
  
  
  /* ============================================================
    MODAL — ADICIONAR MONITOR
  ============================================================ */
  
  function openAddModal() { document.getElementById('addModal').classList.add('open');    }
  function closeModal()    { document.getElementById('addModal').classList.remove('open'); }
  
  
  /* ============================================================
    CRUD DE MONITORS (WATCHES)
  ============================================================ */
  
  /** Adiciona novo monitor após validações. */
  function addWatch() {
    // Rate limit: máx 10 monitors por usuário
    if (state.watches.length >= 10) {
      toast('Limite de 10 monitors atingido (rate limit)', 'warn');
      return;
    }
  
    const name     = document.getElementById('newName').value.trim();
    const url      = document.getElementById('newUrl').value.trim();
    const interval = parseInt(document.getElementById('newInterval').value);
    const selector = document.getElementById('newSelector').value.trim();
    const email    = document.getElementById('newEmail').value.trim();
  
    if (!name || !url) { toast('Nome e URL são obrigatórios', 'warn'); return; }
  
    // Validação SSRF antes de salvar
    const check = validateUrl(url);
    if (!check.ok) { toast('URL inválida: ' + check.reason, 'error'); return; }
  
    const watch = {
      id: 'w_' + Date.now(),
      name, url, interval, selector, email,
      active: true, status: 'pending',
      lastChecked: null, changes: 0, errors: 0,
    };
  
    state.watches.push(watch);
    addActivity(`Monitor "${name}" adicionado`, 'ok', url);
    saveState();
    renderAll();
    closeModal();
  
    // Limpar campos
    ['newName', 'newUrl', 'newSelector', 'newEmail'].forEach(id => {
      document.getElementById(id).value = '';
    });
  
    toast('Monitor adicionado!', 'ok');
  
    // Primeiro scan automático após 800ms
    setTimeout(() => scanWatch(watch.id), 800);
  }
  
  /** Remove um monitor e seu snapshot. */
  function removeWatch(id) {
    const w = state.watches.find(w => w.id === id);
    if (!w) return;
  
    state.watches = state.watches.filter(w => w.id !== id);
    delete state.snapshots[id];
  
    addActivity(`Monitor "${w.name}" removido`, 'error');
    saveState();
    renderAll();
    toast('Monitor removido', 'warn');
  }
  
  /** Pausa ou retoma um monitor. */
  function toggleWatch(id) {
    const w = state.watches.find(w => w.id === id);
    if (!w) return;
  
    w.active = !w.active;
    addActivity(`Monitor "${w.name}" ${w.active ? 'ativado' : 'pausado'}`, w.active ? 'ok' : 'warn');
    saveState();
    renderAll();
    toast(`Monitor ${w.active ? 'ativado' : 'pausado'}`, w.active ? 'ok' : 'warn');
  }
  
  
  /* ============================================================
    SCANNING — VERIFICAÇÃO DE MUDANÇAS
  ============================================================ */
  
  /**
   * Simula um fetch + diff para um monitor.
   * Em produção: Puppeteer/Axios no backend + hash SHA-256.
   */
  function scanWatch(id) {
    const w = state.watches.find(w => w.id === id);
    if (!w || !w.active) return;
  
    w.status = 'scanning';
    renderAll();
  
    // Simula latência de rede (1.2s a 2s)
    setTimeout(() => {
      w.lastChecked = new Date().toISOString();
  
      // Conteúdo simulado: alterna entre v1 e v2 para forçar diff na demo
      const mock = MOCK_CONTENT[w.url];
      const old  = state.snapshots[id];
      let newContent;
  
      if (mock) {
        newContent = (old && old.content === mock.v1) ? mock.v2 : mock.v1;
      } else {
        const templates = [
          `<html><body><h1>${w.name}</h1><p>Conteúdo simulado versão ${Date.now() % 100}</p><div class="price">R$ ${(Math.random() * 500 + 50).toFixed(2)}</div></body></html>`,
          `<html><body><h1>${w.name}</h1><p>Página atualizada em ${new Date().toLocaleDateString('pt-BR')}</p><p>Status: operacional</p></body></html>`,
        ];
        newContent = templates[Math.floor(Math.random() * templates.length)];
      }
  
      // Hash simples para detectar mudança sem comparar texto inteiro
      const hash = simpleHash(newContent);
  
      if (old && old.hash !== hash) {
        // MUDANÇA DETECTADA
        w.status   = 'changed';
        w.changes  = (w.changes || 0) + 1;
        const diff = computeDiff(old.content, newContent);
        state.snapshots[id] = { content: newContent, hash, prev: old.content, diff, time: w.lastChecked };
        addActivity(`Mudança detectada em "${w.name}"`, 'change', w.url);
        toast(`⚡ Mudança em "${w.name}"!`, 'warn');
  
      } else {
        // SEM MUDANÇA
        w.status = 'ok';
        if (!old) {
          state.snapshots[id] = { content: newContent, hash, prev: null, diff: null, time: w.lastChecked };
        }
        addActivity(`Verificação ok: "${w.name}"`, 'ok', w.url);
      }
  
      saveState();
      renderAll();
  
    }, 1200 + Math.random() * 800);
  }
  
  /** Escaneia todos os monitors ativos em sequência. */
  function scanAll() {
    const btn    = document.getElementById('scanAllBtn');
    btn.classList.add('scanning');
    btn.textContent = '⟳ verificando...';
  
    const ativos = state.watches.filter(w => w.active);
    let count = 0;
  
    ativos.forEach((w, i) => {
      setTimeout(() => {
        scanWatch(w.id);
        count++;
        if (count === ativos.length) {
          setTimeout(() => {
            btn.classList.remove('scanning');
            btn.textContent = '⟳ verificar todos';
          }, 1500);
        }
      }, i * 400); // Escalonado para não sobrecarregar
    });
  
    if (!ativos.length) {
      btn.classList.remove('scanning');
      btn.textContent = '⟳ verificar todos';
    }
  }
  
  /** Scheduler automático: verifica URLs cujo intervalo venceu. */
  function startScheduler() {
    state.schedulerInterval = setInterval(() => {
      state.watches.filter(w => w.active).forEach(w => {
        const last    = w.lastChecked ? new Date(w.lastChecked) : null;
        const diffMin = last ? (Date.now() - last.getTime()) / 60000 : Infinity;
        if (diffMin >= w.interval) scanWatch(w.id);
      });
    }, 60000); // Checa a cada minuto
  }
  
  
  /* ============================================================
    DIFF ENGINE
  ============================================================ */
  
  /**
   * Compara duas strings linha a linha.
   * Retorna array de { type: 'add'|'del'|'ctx', ln, text }.
   *
   * Em produção: usar jsdiff no backend e retornar patch unificado.
   */
  function computeDiff(oldText, newText) {
    const oldLines = oldText.split('\n');
    const newLines = newText.split('\n');
    const diff     = [];
    const maxLen   = Math.max(oldLines.length, newLines.length);
  
    for (let i = 0; i < maxLen; i++) {
      if      (i >= oldLines.length)           diff.push({ type: 'add', ln: i + 1, text: newLines[i] });
      else if (i >= newLines.length)           diff.push({ type: 'del', ln: i + 1, text: oldLines[i] });
      else if (oldLines[i] !== newLines[i]) {
        diff.push({ type: 'del', ln: i + 1, text: oldLines[i] });
        diff.push({ type: 'add', ln: i + 1, text: newLines[i] });
      } else {
        diff.push({ type: 'ctx', ln: i + 1, text: oldLines[i] });
      }
    }
  
    return diff;
  }
  
  /**
   * Hash simples (djb2) para detectar mudança sem armazenar conteúdo inteiro.
   * Em produção: SHA-256 no backend (crypto.createHash).
   */
  function simpleHash(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) {
      h = Math.imul(31, h) + str.charCodeAt(i) | 0;
    }
    return h.toString(16);
  }
  
  
  /* ============================================================
    ACTIVITY FEED
  ============================================================ */
  
  /** Adiciona item ao feed de atividade. */
  function addActivity(msg, type, url) {
    state.activity.unshift({ msg, type, url, time: new Date().toISOString() });
    if (state.activity.length > 50) state.activity.pop(); // cap em 50 itens
  }
  
  
  /* ============================================================
    PERSISTÊNCIA — localStorage
  ============================================================ */
  
  /** Salva estado do usuário no localStorage. */
  function saveState() {
    if (!state.user) return;
    localStorage.setItem('wd_watches_'  + state.user.id, JSON.stringify(state.watches));
    localStorage.setItem('wd_snaps_'    + state.user.id, JSON.stringify(state.snapshots));
    localStorage.setItem('wd_activity_' + state.user.id, JSON.stringify(state.activity.slice(0, 50)));
  }
  
  
  /* ============================================================
    RENDER — ATUALIZAÇÃO DA UI
  ============================================================ */
  
  /** Re-renderiza todos os componentes. */
  function renderAll() {
    renderMetrics();
    renderWatchTable();
    renderSidebar();
    renderActivity();
  }
  
  function renderMetrics() {
    const total   = state.watches.length;
    const active  = state.watches.filter(w => w.active).length;
    const changes = state.watches.filter(w => w.status === 'changed').length;
    const errors  = state.watches.filter(w => w.status === 'error').length;
  
    document.getElementById('mTotal').textContent   = total;
    document.getElementById('mActive').textContent  = active;
    document.getElementById('mChanges').textContent = changes;
    document.getElementById('mErrors').textContent  = errors;
  }
  
  function renderSidebar() {
    const c = document.getElementById('sidebarWatches');
  
    if (!state.watches.length) {
      c.innerHTML = '<div style="padding:4px 8px;font-size:11px;color:var(--text3);font-family:var(--mono)">nenhum ainda</div>';
      return;
    }
  
    c.innerHTML = state.watches.map(w => {
      const dot   = w.status === 'changed' ? 'dot-amber' : w.status === 'error' ? 'dot-red' : w.active ? 'dot-green' : '';
      const label = new URL(w.url).hostname.replace('www.', '');
  
      return `<a class="nav-item"
        onclick="showView('diffs',this);setTimeout(()=>{document.getElementById('diffSelect').value='${w.id}';loadDiff()},100)"
        style="font-size:12px;font-family:var(--mono)">
        ${label} ${dot ? `<span class="dot ${dot}"></span>` : ''}
      </a>`;
    }).join('');
  }
  
  function renderActivity() {
    const c = document.getElementById('activityFeed');
  
    if (!state.activity.length) {
      c.innerHTML = '<div class="empty" style="padding:30px"><div class="empty-icon">◎</div><h3>sem atividade ainda</h3><p>adicione um site para monitorar</p></div>';
      return;
    }
  
    c.innerHTML = state.activity.slice(0, 12).map(a => {
      const dt       = new Date(a.time);
      const ts       = dt.toLocaleDateString('pt-BR') + ' ' + dt.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
      const dotClass = a.type === 'change' ? 'tl-dot-change' : a.type === 'error' ? 'tl-dot-error' : 'tl-dot-ok';
  
      return `<div class="tl-item">
        <div class="tl-dot ${dotClass}"></div>
        <div class="tl-time">${ts}</div>
        <div class="tl-desc">${a.msg}</div>
      </div>`;
    }).join('');
  }
  
  function renderWatchTable() {
    const tbody = document.getElementById('watchTableBody');
  
    if (!state.watches.length) {
      tbody.innerHTML = '<tr><td colspan="6"><div class="empty"><div class="empty-icon">◎</div><h3>nenhum monitor</h3><p>clique em "+ novo monitor" para começar</p></div></td></tr>';
      return;
    }
  
    const intervals = { 1: '1min', 60: '1h', 360: '6h', 1440: '24h' };
  
    tbody.innerHTML = state.watches.map(w => {
      const lastCheck = w.lastChecked
        ? new Date(w.lastChecked).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
        : '—';
  
      const badge = w.status === 'scanning'
        ? '<span class="badge badge-amber scanning">◌ escaneando</span>'
        : w.status === 'changed' ? '<span class="badge badge-amber">⚡ mudança</span>'
        : w.status === 'error'   ? '<span class="badge badge-red">✗ erro</span>'
        : w.active               ? '<span class="badge badge-green">● ativo</span>'
        :                          '<span class="badge badge-gray">◌ pausado</span>';
  
      const snap     = state.snapshots[w.id];
      const diffInfo = snap && snap.diff
        ? `<div class="change-bar">
            <span class="change-pill change-add">+${snap.diff.filter(d => d.type === 'add').length}</span>
            <span class="change-pill change-del">-${snap.diff.filter(d => d.type === 'del').length}</span>
          </div>`
        : `<span style="color:var(--text3);font-size:12px">${w.changes || 0} total</span>`;
  
      return `<tr>
        <td>
          <div class="name-cell">${esc(w.name)}</div>
          <div class="url-cell">${esc(w.url)}</div>
        </td>
        <td>${badge}</td>
        <td><span style="font-family:var(--mono);font-size:12px;color:var(--text2)">${intervals[w.interval] || w.interval + 'min'}</span></td>
        <td><span style="font-family:var(--mono);font-size:12px;color:var(--text2)">${lastCheck}</span></td>
        <td>${diffInfo}</td>
        <td>
          <div style="display:flex;gap:6px;justify-content:flex-end">
            <button class="btn btn-sm" onclick="scanWatch('${w.id}')">⟳</button>
            <button class="btn btn-sm" onclick="toggleWatch('${w.id}')">${w.active ? '⏸' : '▶'}</button>
            <button class="btn btn-sm btn-danger" onclick="removeWatch('${w.id}')">✕</button>
          </div>
        </td>
      </tr>`;
    }).join('');
  }
  
  
  /* ============================================================
    DIFF VIEWER
  ============================================================ */
  
  function populateDiffSelect() {
    const sel = document.getElementById('diffSelect');
    const cur = sel.value;
  
    sel.innerHTML = '<option value="">— escolha um site —</option>';
    state.watches.forEach(w => {
      const opt       = document.createElement('option');
      opt.value       = w.id;
      opt.textContent = w.name + (state.snapshots[w.id]?.diff ? ' ⚡' : '');
      sel.appendChild(opt);
    });
  
    if (cur) sel.value = cur;
  }
  
  function loadDiff() {
    const id   = document.getElementById('diffSelect').value;
    const cont = document.getElementById('diffOutput');
  
    if (!id) {
      cont.innerHTML = '<div class="empty"><div class="empty-icon">⟷</div><h3>nenhum diff selecionado</h3><p>escolha um site com mudanças detectadas</p></div>';
      return;
    }
  
    const w    = state.watches.find(w => w.id === id);
    const snap = state.snapshots[id];
  
    if (!snap || !snap.diff) {
      cont.innerHTML = `<div class="empty"><div class="empty-icon">✓</div><h3>nenhuma mudança detectada</h3><p>O conteúdo de "${w.name}" não mudou desde o primeiro snapshot.</p></div>`;
      return;
    }
  
    const adds = snap.diff.filter(d => d.type === 'add').length;
    const dels = snap.diff.filter(d => d.type === 'del').length;
  
    // Mostrar apenas contexto relevante (±2 linhas ao redor das mudanças)
    const relevant = [];
    snap.diff.forEach((line, i) => {
      if (line.type !== 'ctx') {
        for (let j = Math.max(0, i - 2); j <= Math.min(snap.diff.length - 1, i + 2); j++) {
          if (!relevant.includes(snap.diff[j])) relevant.push(snap.diff[j]);
        }
      }
    });
  
    cont.innerHTML = `
      <div class="card" style="padding:0;overflow:hidden">
        <div style="padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px">
          <span style="font-family:var(--display);font-size:14px;font-weight:700">${esc(w.name)}</span>
          <span class="change-pill change-add">+${adds} linhas</span>
          <span class="change-pill change-del">-${dels} linhas</span>
          <span style="font-size:11px;color:var(--text3);margin-left:auto;font-family:var(--mono)">${new Date(snap.time).toLocaleString('pt-BR')}</span>
        </div>
        <div class="diff-container" style="border:none;border-radius:0">
          <div class="diff-header">
            <span style="color:var(--text3)">mostrando contexto relevante ±2 linhas</span>
          </div>
          ${relevant.length
            ? relevant.map(line => `
                <div class="diff-line ${line.type === 'add' ? 'diff-add' : line.type === 'del' ? 'diff-del' : 'diff-ctx'}">
                  <span class="diff-ln">${line.ln}</span>
                  <span class="diff-content">${line.type === 'add' ? '+ ' : line.type === 'del' ? '- ' : '  '}${esc(line.text)}</span>
                </div>`).join('')
            : '<div style="padding:12px 16px;color:var(--text3);font-family:var(--mono);font-size:12px">sem diferenças para mostrar</div>'
          }
        </div>
      </div>`;
  }
  
  
  /* ============================================================
    SEGURANÇA — DEMOS INTERATIVAS
  ============================================================ */
  
  /** Testa validação SSRF em tempo real. */
  function testSSRF() {
    const url = document.getElementById('ssrfInput').value.trim();
    if (!url) { toast('Digite uma URL para testar', 'warn'); return; }
  
    const res = validateUrl(url);
    const el  = document.getElementById('ssrfResult');
    el.className  = 'ssrf-result ' + (res.ok ? 'ssrf-ok' : 'ssrf-fail');
    el.textContent = res.ok
      ? '✓ SSRF guard: URL aprovada — pode ser monitorada'
      : '✗ SSRF guard: URL BLOQUEADA — ' + res.reason;
  }
  
  function setSSRF(url) {
    document.getElementById('ssrfInput').value = url;
    testSSRF();
  }
  
  /** Demo de hash bcrypt no browser. */
  function hashPassword() {
    const pass = document.getElementById('bcryptInput').value;
    if (!pass) { toast('Digite uma senha', 'warn'); return; }
  
    const el       = document.getElementById('bcryptResult');
    el.textContent = 'gerando hash...';
    el.style.color = 'var(--text3)';
  
    // setTimeout para não bloquear a UI durante o hash
    setTimeout(() => {
      const hash = bcrypt.hashSync(pass, 10);
      const ok   = bcrypt.compareSync(pass, hash);
  
      el.innerHTML = `
        <span style="color:var(--text2)">hash: </span>
        <span style="color:var(--accent)">${hash}</span><br><br>
        <span style="color:var(--text3)">verificação: ${
          ok
            ? '<span style="color:var(--green)">✓ senha correta</span>'
            : '<span style="color:var(--red)">✗ inválida</span>'
        }</span>`;
    }, 100);
  }
  
  
  /* ============================================================
    TOAST — NOTIFICAÇÕES
  ============================================================ */
  
  function toast(msg, type = 'ok') {
    const icons  = { ok: '✓', warn: '!', error: '✗', info: 'i' };
    const colors = { ok: 'var(--green)', warn: 'var(--amber)', error: 'var(--red)', info: 'var(--accent)' };
  
    const el      = document.createElement('div');
    el.className  = 'toast';
    el.innerHTML  = `<span style="color:${colors[type]};font-weight:700;font-size:15px">${icons[type]}</span> ${msg}`;
  
    document.getElementById('toastWrap').appendChild(el);
    setTimeout(() => el.remove(), 3500);
  }
  
  
  /* ============================================================
    UTILITÁRIOS
  ============================================================ */
  
  /** Escapa HTML para prevenir XSS ao renderizar conteúdo externo. */
  function esc(s) {
    return String(s)
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;');
  }
  
  
  /* ============================================================
    DADOS DEMO — PRÉ-CARREGAMENTO
  ============================================================ */
  
  const DEMO_WATCHES = [
    {
      id:          'w_demo1',
      name:        'Example.com',
      url:         'https://example.com',
      interval:    60,
      selector:    '',
      email:       'demo@watchdiff.io',
      active:      true,
      status:      'ok',
      lastChecked: new Date(Date.now() - 1800000).toISOString(),
      changes:     1,
      errors:      0,
    },
    {
      id:          'w_demo2',
      name:        'HTTPBin API',
      url:         'https://httpbin.org/get',
      interval:    360,
      selector:    '',
      email:       '',
      active:      true,
      status:      'changed',
      lastChecked: new Date(Date.now() - 600000).toISOString(),
      changes:     2,
      errors:      0,
    },
  ];
  
  /** Popula localStorage com dados demo na primeira visita. */
  function initDemoData() {
    if (localStorage.getItem('wd_watches_demo')) return; // já inicializado
  
    const snaps = {};
  
    const diff1 = computeDiff(
      MOCK_CONTENT['https://example.com'].v1,
      MOCK_CONTENT['https://example.com'].v2
    );
    snaps['w_demo1'] = {
      content: MOCK_CONTENT['https://example.com'].v2,
      hash:    simpleHash(MOCK_CONTENT['https://example.com'].v2),
      prev:    MOCK_CONTENT['https://example.com'].v1,
      diff:    diff1,
      time:    DEMO_WATCHES[0].lastChecked,
    };
  
    const diff2 = computeDiff(
      MOCK_CONTENT['https://httpbin.org/get'].v1,
      MOCK_CONTENT['https://httpbin.org/get'].v2
    );
    snaps['w_demo2'] = {
      content: MOCK_CONTENT['https://httpbin.org/get'].v2,
      hash:    simpleHash(MOCK_CONTENT['https://httpbin.org/get'].v2),
      prev:    MOCK_CONTENT['https://httpbin.org/get'].v1,
      diff:    diff2,
      time:    DEMO_WATCHES[1].lastChecked,
    };
  
    const activity = [
      { msg: 'Mudança detectada em "HTTPBin API"', type: 'change', url: 'https://httpbin.org/get', time: DEMO_WATCHES[1].lastChecked },
      { msg: 'Mudança detectada em "Example.com"', type: 'change', url: 'https://example.com',     time: DEMO_WATCHES[0].lastChecked },
      { msg: 'Monitor "HTTPBin API" adicionado',   type: 'ok',                                      time: new Date(Date.now() - 3600000).toISOString() },
      { msg: 'Monitor "Example.com" adicionado',   type: 'ok',                                      time: new Date(Date.now() - 7200000).toISOString() },
    ];
  
    localStorage.setItem('wd_watches_demo',  JSON.stringify(DEMO_WATCHES));
    localStorage.setItem('wd_snaps_demo',    JSON.stringify(snaps));
    localStorage.setItem('wd_activity_demo', JSON.stringify(activity));
  }