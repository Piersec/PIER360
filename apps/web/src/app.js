(function () {
  const data = window.PIER360Data;
  const pageRoot = document.getElementById('pageContent');
  const modalRoot = document.getElementById('modalRoot');
  const toastRoot = document.getElementById('toastRegion');
  const titles = { overview: 'Visão geral', agents: 'Ativos', vulnerabilities: 'Vulnerabilidades', admin: 'Administração' };
  const state = {
    page: 'overview', activeTenant: data.getActiveTenant(), priorityTenant: data.getActiveTenant(),
    agentQuery: '', agentStatus: 'all', agentPriority: 'all', agentCritical: 'all',
    vulnQuery: '', vulnSeverity: 'all', vulnStatus: 'all', vulnKev: 'all', vulnMinEpss: '', vulnPriority: 'all',
    userQuery: '', userStatus: 'all', editingUser: null,
  };

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
  const number = (value) => new Intl.NumberFormat('pt-BR').format(value);
  const percent = (value) => `${(Number(value) * 100).toFixed(1).replace('.', ',')}%`;
  const dateShort = (value) => new Intl.DateTimeFormat('pt-BR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(value));
  const initials = (name = '') => name.split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0]).join('').toUpperCase();

  function severityClass(value) {
    return ({ 'Crítica': 'severity-critical', 'Alta': 'severity-high', 'Média': 'severity-medium', 'Baixa': 'severity-low' })[value] || 'severity-low';
  }
  function severityPill(value) { return `<span class="severity-pill ${severityClass(value)}">${escapeHtml(value)}</span>`; }
  function priorityBadge(priority) {
    const key = (priority?.key || 'pending').replaceAll('_', '-');
    return `<span class="priority-badge priority-${escapeHtml(key)}" title="${escapeHtml(priority?.reason || '')}">${escapeHtml(priority?.label || 'EPSS pendente')}</span>`;
  }
  function statusPill(value) {
    const map = {
      active: ['Ativo', 'status-active'], disconnected: ['Desconectado', 'status-disconnected'], pending: ['Pendente', 'status-pending'],
      'Sem tratamento': ['Sem tratamento', 'status-neutral'], 'Atribuída': ['Atribuída', 'status-treatment'],
      'Em correção': ['Em correção', 'status-work'], 'Correção aplicada': ['Correção aplicada', 'status-done'],
      'Risco aceito': ['Risco aceito', 'status-pending'], 'Falso positivo': ['Falso positivo', 'status-neutral'],
      'Ativo': ['Ativo', 'status-active'], 'Convidado': ['Convidado', 'status-pending'], 'Desativado': ['Desativado', 'status-neutral'],
    };
    const [label, cls] = map[value] || [value, 'status-neutral'];
    return `<span class="status-pill ${cls}">${escapeHtml(label)}</span>`;
  }
  function kevPill(value) { return value ? '<span class="kev-pill">KEV</span>' : '<span class="kev-pill not-kev">Não KEV</span>'; }
  function pageHeading(title, description, actions = '') {
    return `<div class="page-heading"><div><div class="eyebrow"><span class="eyebrow-mark"></span>PIER360 · Plataforma de segurança</div><h1>${title}</h1><p class="page-subtitle">${description}</p></div><div class="heading-actions">${actions}</div></div>`;
  }
  function demoNotice(message = 'Interface em desenvolvimento. Os valores exibidos são sintéticos e não representam dados de produção.') {
    return `<div class="inline-demo-note"><strong>DEMO</strong><span>${message}</span></div>`;
  }
  function emptyRow(cols, msg = 'Nenhum resultado encontrado para estes filtros.') { return `<tr><td colspan="${cols}"><div class="empty-state">${msg}</div></td></tr>`; }

  function trendPath(values, width = 646, height = 132, maxValue = 50, left = 44, top = 12) {
    const points = values.map((value, index) => ({
      x: left + index * width / Math.max(1, values.length - 1),
      y: top + height - Math.min(value, maxValue) / maxValue * height,
    }));
    return points.reduce((path, point, index) => {
      if (index === 0) return `M ${point.x} ${point.y}`;
      const previous = points[index - 1];
      const handle = (point.x - previous.x) * 0.42;
      return `${path} C ${previous.x + handle} ${previous.y}, ${point.x - handle} ${point.y}, ${point.x} ${point.y}`;
    }, '');
  }

  async function renderOverview() {
    const metrics = await data.getOverview(state.activeTenant);
    const findings = await data.listFindings({ tenantId: state.activeTenant });
    const agents = await data.listAgents({ tenantId: state.activeTenant });
    const severityData = [
      { label: 'Crítica', key: 'critical', count: metrics.critical },
      { label: 'Alta', key: 'high', count: metrics.high },
      { label: 'Média', key: 'medium', count: metrics.medium },
      { label: 'Baixa', key: 'low', count: metrics.low },
    ];
    const severityCards = severityData.map((s) => `<article class="severity-summary-card ${s.key}"><strong>${number(s.count)}</strong><span>${s.label.toUpperCase()}</span></article>`).join('');
    const trend = metrics.trend;
    const trendMax = 50;
    const trendSeries = [
      { key: 'critical', label: 'Crítica' }, { key: 'high', label: 'Alta' },
      { key: 'medium', label: 'Média' }, { key: 'low', label: 'Baixa' },
    ];
    const trendPaths = trendSeries.map((series) => {
      const path = trendPath(trend.map((point) => point[series.key] || 0), 646, 132, trendMax, 44, 12);
      const area = `${path} L 690 144 L 44 144 Z`;
      return `<path class="trend-area ${series.key}" d="${area}"/><path class="trend-line ${series.key}" d="${path}"/>`;
    }).join('');
    const thresholdPercent = Number((metrics.priorityConfig.epssThreshold * 100).toFixed(1));
    const topPriorityRows = findings.slice(0, 5);
    const assetPriorityRows = agents.filter((agent) => agent.priorityCount > 0)
      .sort((a, b) => b.priorityCount - a.priorityCount || b.kevCount - a.kevCount || a.name.localeCompare(b.name)).slice(0, 5);

    pageRoot.innerHTML = `
      ${pageHeading('Visão geral de segurança', `Prioridade por KEV e EPSS · tenant ${escapeHtml(state.activeTenant)}.`, `<button class="date-control" data-action="date-range">◷ &nbsp;Últimos 30 dias&nbsp;⌄</button><button class="secondary-button" data-action="refresh-demo">↻ &nbsp;Atualizar</button>`)}
      <div class="severity-strip" aria-label="Vulnerabilidades por severidade">${severityCards}</div>
      <section class="priority-formula-strip"><div class="priority-formula-mark">↕</div><div><strong>Ordem aplicada neste tenant</strong><p><b>KEV ativo primeiro</b> · depois EPSS ≥ ${String(thresholdPercent).replace('.', ',')}%, em ordem decrescente. O indicador combinado destaca KEV ativo + EPSS ≥ o corte. EPSS ausente permanece sem classificação. CVSS e criticidade do ativo são contexto.</p></div><button class="panel-action" data-page="admin">Configurar corte EPSS →</button></section>
      <div class="risk-metric-grid">
        <article class="risk-metric-card"><h2>KEV + EPSS ≥ ${String(thresholdPercent).replace('.', ',')}%</h2><strong>${number(metrics.kevAndHighEpss)}</strong><p>Vulnerabilidades no KEV com probabilidade EPSS acima do corte</p><button class="panel-action" data-priority-nav="kev_epss_high">Ver vulnerabilidades →</button></article>
        <article class="risk-metric-card"><h2>KEV ativo</h2><strong>${number(metrics.kevActive)}</strong><p>Vulnerabilidades listadas no catálogo CISA KEV, qualquer que seja o EPSS</p><button class="panel-action" data-priority-nav="kev">Ver vulnerabilidades →</button></article>
        <article class="risk-metric-card"><h2>EPSS ≥ ${String(thresholdPercent).replace('.', ',')}%</h2><strong>${number(metrics.highEpss)}</strong><p>Probabilidade elevada de exploração, com ou sem presença no KEV</p><button class="panel-action" data-priority-nav="epss_high">Ver vulnerabilidades →</button></article>
      </div>
      <section class="panel trend-panel">
        <div class="panel-heading"><div><h2 class="panel-title">Tendência ao longo do tempo</h2><div class="panel-caption">Vulnerabilidades por severidade · dados DEMO</div></div><div class="trend-legend">${trendSeries.map((s) => `<span class="${s.key}">${s.label}</span>`).join('')}</div></div>
        <div class="trend-chart-wrap"><svg class="trend-chart" viewBox="0 0 700 176" preserveAspectRatio="none" role="img" aria-label="Tendência de vulnerabilidades por severidade nos últimos cinco períodos">
          <defs><linearGradient id="fill-critical" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#830727" stop-opacity=".22"/><stop offset="100%" stop-color="#830727" stop-opacity="0"/></linearGradient><linearGradient id="fill-high" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#df3025" stop-opacity=".2"/><stop offset="100%" stop-color="#df3025" stop-opacity="0"/></linearGradient><linearGradient id="fill-medium" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#ed7d1b" stop-opacity=".18"/><stop offset="100%" stop-color="#ed7d1b" stop-opacity="0"/></linearGradient><linearGradient id="fill-low" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#e8bd1b" stop-opacity=".16"/><stop offset="100%" stop-color="#e8bd1b" stop-opacity="0"/></linearGradient></defs>
          <g class="trend-grid"><line x1="42" y1="12" x2="698" y2="12"/><line x1="42" y1="78" x2="698" y2="78"/><line x1="42" y1="144" x2="698" y2="144"/></g><g class="trend-axis"><text x="8" y="16">50</text><text x="8" y="82">25</text><text x="18" y="148">0</text></g>${trendPaths}
        </svg><div class="trend-labels">${trend.map((point) => `<span>${escapeHtml(point.month)}</span>`).join('')}</div></div>
      </section>
      <div class="overview-tables">
        <section class="panel dashboard-panel priority-queue-panel"><div class="panel-heading"><div><h2 class="panel-title">ORDEM DE PRIORIZAÇÃO</h2><div class="panel-caption">KEV ativo primeiro; depois EPSS em ordem decrescente</div></div><button class="panel-action" data-page="vulnerabilities">Ver mais →</button></div>
          <table class="compact-table priority-queue-table"><thead><tr><th>Critério</th><th>CVE / pacote</th><th>Ativo</th><th>EPSS</th></tr></thead><tbody>${topPriorityRows.length ? topPriorityRows.map((f) => `<tr data-finding="${f.id}"><td>${priorityBadge(f.priority)}</td><td><strong title="${escapeHtml(f.cve)}">${escapeHtml(f.cve)}</strong><span class="sub-cell" title="${escapeHtml(f.package)}">${escapeHtml(f.package)}</span></td><td title="${escapeHtml(f.agent)}">${escapeHtml(f.agent)}</td><td>${Number.isFinite(f.epss) ? percent(f.epss) : 'Pendente'}</td></tr>`).join('') : emptyRow(4, 'Nenhuma vulnerabilidade neste tenant.')}</tbody></table>
        </section>
        <section class="panel dashboard-panel"><div class="panel-heading"><div><h2 class="panel-title">Ativos impactados</h2><div class="panel-caption">As contagens KEV e EPSS podem se sobrepor</div></div><button class="panel-action" data-page="agents">Ver ativos →</button></div>
          <div class="table-scroll"><table class="compact-table"><thead><tr><th>Ativo / IP</th><th>KEV ativo</th><th>EPSS ≥ corte</th><th>Crítico</th></tr></thead><tbody>${assetPriorityRows.length ? assetPriorityRows.map((agent) => `<tr data-agent="${agent.id}"><td><strong>${escapeHtml(agent.name)}</strong><span class="sub-cell">${escapeHtml(agent.ip)}</span></td><td>${number(agent.kevCount)}</td><td>${number(agent.highEpssCount)}</td><td>${agent.isCritical ? '<span class="asset-critical-tag">Sim · PUS</span>' : 'Não'}</td></tr>`).join('') : emptyRow(4, 'Nenhum ativo impactado por KEV ou EPSS alto neste tenant.')}</tbody></table></div>
        </section>
        <section class="panel dashboard-panel corrections-panel"><div class="panel-heading"><div><h2 class="panel-title">Corrigidas · últimos 30 dias</h2><div class="panel-caption">Status PUS atualizado no tenant ${escapeHtml(state.activeTenant)}</div></div></div><div class="corrections-empty"><span>✓</span><p>${metrics.correctedLast30Days ? `${number(metrics.correctedLast30Days)} vulnerabilidades marcadas como corrigidas no período.` : 'Nenhuma correção registrada nos últimos 30 dias.'}</p></div></section>
      </div>
      ${demoNotice('Todos os indicadores, scores e tendências desta visão são sintéticos. Os valores reais virão do Wazuh e dos enriquecimentos EPSS/CISA KEV.')}`;
  }

  async function renderAgents() {
    const metrics = await data.getOverview(state.activeTenant);
    const rows = await data.listAgents({ tenantId: state.activeTenant, query: state.agentQuery, status: state.agentStatus, priority: state.agentPriority, critical: state.agentCritical });
    const all = await data.listAgents({ tenantId: state.activeTenant });
    const actions = `<button class="secondary-button" data-action="refresh-demo">↻ &nbsp;Atualizar</button>`;
    pageRoot.innerHTML = `
      ${pageHeading('Ativos monitorados', 'Inventário de agents, conectividade e último scan do Syscollector.', actions)}
      <div class="metric-grid">
        <article class="metric-card"><div class="metric-top"><span>Total de agents</span><span class="metric-icon">▦</span></div><div class="metric-value">${number(metrics.totalAgents)}</div><div class="metric-footer"><strong>${number(metrics.activeAgents)} ativos</strong><span>${number(metrics.disconnectedAgents)} desconectados · ${number(metrics.pendingAgents)} pendentes</span></div><div class="metric-accent-line"></div></article>
        <article class="metric-card"><div class="metric-top"><span>Ativos</span><span class="metric-icon">●</span></div><div class="metric-value">${number(metrics.activeAgents)}</div><div class="metric-footer"><strong>${metrics.totalAgents ? percent(metrics.activeAgents / metrics.totalAgents) : '—'}</strong><span>com heartbeat</span></div><div class="metric-accent-line"></div></article>
        <article class="metric-card"><div class="metric-top"><span>Desconectados</span><span class="metric-icon red">●</span></div><div class="metric-value">${number(metrics.disconnectedAgents)}</div><div class="metric-footer"><strong>Verificar último contato</strong></div><div class="metric-accent-line red-line"></div></article>
        <article class="metric-card"><div class="metric-top"><span>Ativos Críticos</span><span class="metric-icon">◆</span></div><div class="metric-value">${number(metrics.criticalAssets)}</div><div class="metric-footer"><strong>${number(metrics.criticalAssetVulnerabilities)} vulnerabilidades associadas</strong></div><div class="metric-accent-line"></div></article>
      </div>
      <div class="toolbar">
        <label class="search-field"><span>⌕</span><input data-filter="agentQuery" value="${escapeHtml(state.agentQuery)}" placeholder="Buscar por hostname, IP ou ID" /></label>
        <select class="select-filter" data-filter="agentStatus"><option value="all">Todos os status</option><option value="active" ${state.agentStatus === 'active' ? 'selected' : ''}>Ativos</option><option value="disconnected" ${state.agentStatus === 'disconnected' ? 'selected' : ''}>Desconectados</option><option value="pending" ${state.agentStatus === 'pending' ? 'selected' : ''}>Pendentes</option></select>
        <select class="select-filter" data-filter="agentPriority"><option value="all">Todas as faixas</option><option value="kev" ${state.agentPriority === 'kev' ? 'selected' : ''}>Com KEV ativo</option><option value="epss_high" ${state.agentPriority === 'epss_high' ? 'selected' : ''}>Com EPSS ≥ ${String((metrics.priorityConfig.epssThreshold * 100).toFixed(1)).replace('.', ',')}%</option></select>
        <select class="select-filter" data-filter="agentCritical"><option value="all" ${state.agentCritical === 'all' ? 'selected' : ''}>Todos os ativos</option><option value="yes" ${state.agentCritical === 'yes' ? 'selected' : ''}>Ativos críticos</option><option value="no" ${state.agentCritical === 'no' ? 'selected' : ''}>Não críticos</option></select>
        <span class="filter-count">${number(rows.length)} de ${number(all.length)} agents de demonstração</span>
      </div>
      <section class="table-card"><div class="table-scroll"><table class="asset-table"><thead><tr><th>Agent</th><th>IP</th><th>Sistema operacional</th><th>Status</th><th>Classificação PUS</th><th>Último contato</th><th>Último scan</th><th>Vulnerabilidades</th></tr></thead><tbody>${rows.length ? rows.map((a) => `<tr data-agent="${a.id}"><td><span class="asset-name">${escapeHtml(a.name)}</span><span class="sub-cell">ID ${a.id} · ${escapeHtml(a.group)}</span></td><td>${escapeHtml(a.ip)}</td><td><span class="os-glyph">${a.os.startsWith('Windows') ? 'W' : a.os.startsWith('macOS') ? 'M' : 'L'}</span>${escapeHtml(a.os)}</td><td>${statusPill(a.status)}</td><td><span class="asset-classification ${a.isCritical ? 'is-critical' : ''}">${a.isCritical ? 'Ativo crítico' : 'Não crítico'}</span></td><td>${escapeHtml(a.lastKeepAlive)}</td><td>${escapeHtml(a.scanTime)}</td><td><strong style="color:var(--text)">${a.findings}</strong></td></tr>`).join('') : emptyRow(8)}</tbody></table></div><div class="pagination"><span>Dados de demonstração · conexão Wazuh não configurada</span><div class="page-buttons"><button class="current">1</button><button disabled>2</button><button disabled>→</button></div></div></section>
      ${demoNotice()}`;
  }

  async function renderVulnerabilities() {
    const config = await data.getPriorityConfig(state.activeTenant);
    const thresholdPercent = Number((config.epssThreshold * 100).toFixed(1));
    const rows = await data.listFindings({ tenantId: state.activeTenant, query: state.vulnQuery, severity: state.vulnSeverity, status: state.vulnStatus, kev: state.vulnKev, minEpss: state.vulnMinEpss, priority: state.vulnPriority });
    const all = await data.listFindings({ tenantId: state.activeTenant });
    const kevActive = all.filter((finding) => finding.priority.key === 'kev').length;
    const highEpss = all.filter((finding) => typeof finding.epss === 'number' && Number.isFinite(finding.epss) && finding.epss >= config.epssThreshold).length;
    const belowEpss = all.filter((finding) => finding.priority.key === 'epss_below').length;
    const pendingEpss = all.filter((finding) => finding.priority.key === 'pending').length;
    pageRoot.innerHTML = `
      ${pageHeading('Gestão de vulnerabilidades', `Fila calculada para ${escapeHtml(state.activeTenant)} pela regra KEV → EPSS.`, `<button class="secondary-button" data-action="refresh-demo">↻ &nbsp;Atualizar dados</button>`)}
      <div class="severity-summary section-space" style="margin-bottom:15px">
        <div class="summary-box"><span>Total no recorte demo</span><strong>${number(all.length)}</strong></div>
        <div class="summary-box"><span>KEV ativo</span><strong class="priority-text-kev">${number(kevActive)}</strong></div>
        <div class="summary-box"><span>EPSS ≥ ${String(thresholdPercent).replace('.', ',')}%</span><strong class="priority-text-epss-high">${number(highEpss)}</strong></div>
        <div class="summary-box"><span>EPSS abaixo do limiar</span><strong class="priority-text-epss-below">${number(belowEpss)}</strong></div>
        <div class="summary-box"><span>EPSS pendente</span><strong>${number(pendingEpss)}</strong></div>
      </div>
      <div class="tabs-row"><button class="tab-button ${state.vulnStatus === 'all' ? 'active' : ''}" data-filter-status="all">Todas<span class="tab-count">${all.length}</span></button><button class="tab-button ${state.vulnStatus === 'Sem tratamento' ? 'active' : ''}" data-filter-status="Sem tratamento">Sem tratamento</button><button class="tab-button ${state.vulnStatus === 'Atribuída' ? 'active' : ''}" data-filter-status="Atribuída">Atribuídas</button><button class="tab-button ${state.vulnStatus === 'Em correção' ? 'active' : ''}" data-filter-status="Em correção">Em correção</button><button class="tab-button ${state.vulnStatus === 'Risco aceito' ? 'active' : ''}" data-filter-status="Risco aceito">Risco aceito</button></div>
      <div class="toolbar">
        <label class="search-field"><span>⌕</span><input data-filter="vulnQuery" value="${escapeHtml(state.vulnQuery)}" placeholder="Buscar por CVE, pacote ou ativo" /></label>
        <select class="select-filter" data-filter="vulnSeverity"><option value="all">Todas severidades</option>${['Crítica','Alta','Média','Baixa'].map((s) => `<option ${state.vulnSeverity === s ? 'selected' : ''}>${s}</option>`).join('')}</select>
        <select class="select-filter" data-filter="vulnStatus"><option value="all">Todos os workflows</option>${['Sem tratamento','Atribuída','Em correção','Correção aplicada','Risco aceito','Falso positivo'].map((s) => `<option ${state.vulnStatus === s ? 'selected' : ''}>${s}</option>`).join('')}</select>
        <select class="select-filter" data-filter="vulnKev"><option value="all">KEV e não KEV</option><option value="yes" ${state.vulnKev === 'yes' ? 'selected' : ''}>KEV</option><option value="no" ${state.vulnKev === 'no' ? 'selected' : ''}>Não KEV</option></select>
        <select class="select-filter" data-filter="vulnPriority"><option value="all">Todas as faixas</option><option value="kev_epss_high" ${state.vulnPriority === 'kev_epss_high' ? 'selected' : ''}>KEV ativo + EPSS ≥ ${String(thresholdPercent).replace('.', ',')}%</option><option value="kev" ${state.vulnPriority === 'kev' ? 'selected' : ''}>KEV ativo</option><option value="epss_high" ${state.vulnPriority === 'epss_high' ? 'selected' : ''}>EPSS ≥ ${String(thresholdPercent).replace('.', ',')}%</option><option value="epss_below" ${state.vulnPriority === 'epss_below' ? 'selected' : ''}>EPSS abaixo do limiar</option><option value="pending" ${state.vulnPriority === 'pending' ? 'selected' : ''}>EPSS pendente</option></select>
        <select class="select-filter" data-filter="vulnMinEpss"><option value="">Qualquer EPSS</option><option value="${config.epssThreshold}" ${state.vulnMinEpss === String(config.epssThreshold) ? 'selected' : ''}>Limiar atual (≥${String(thresholdPercent).replace('.', ',')}%)</option><option value="0.5" ${state.vulnMinEpss === '0.5' ? 'selected' : ''}>EPSS ≥ 50%</option><option value="0.7" ${state.vulnMinEpss === '0.7' ? 'selected' : ''}>EPSS ≥ 70%</option></select>
        <span class="filter-count">${number(rows.length)} vulnerabilidades</span>
      </div>
      <section class="table-card"><div class="table-scroll"><table><thead><tr><th>Prioridade</th><th>Vulnerabilidade</th><th>Severidade · contexto</th><th>Ativo impactado</th><th>EPSS</th><th>KEV</th><th>Workflow PUS</th><th>Detectada</th></tr></thead><tbody>${rows.length ? rows.map((f) => `<tr data-finding="${f.id}"><td>${priorityBadge(f.priority)}</td><td><span class="asset-name">${escapeHtml(f.cve)}</span><span class="sub-cell">${escapeHtml(f.package)} ${escapeHtml(f.version)}</span></td><td>${severityPill(f.severity)}<span class="sub-cell">CVSS ${f.cvss.toFixed(1)} · contexto</span></td><td><span class="asset-name">${escapeHtml(f.agent)}</span><span class="sub-cell">${escapeHtml(f.ip)}${f.agentCritical ? ' · Ativo crítico PUS' : ''}</span></td><td>${Number.isFinite(f.epss) ? `<span class="epss-pill">${percent(f.epss)}</span><span class="sub-cell">percentil ${percent(f.percentile / 100)}</span>` : 'Pendente'}</td><td>${kevPill(f.kev)}</td><td>${statusPill(f.status)}</td><td>${escapeHtml(f.detectedAt)}</td></tr>`).join('') : emptyRow(8, `Nenhuma vulnerabilidade neste recorte para ${escapeHtml(state.activeTenant)}.`)}</tbody></table></div><div class="pagination"><span>Exibição de demonstração · ${rows.length} de ${all.length} vulnerabilidades retornadas</span><div class="page-buttons"><button class="current">1</button><button disabled>2</button><button disabled>→</button></div></div></section>
      ${demoNotice('Scores EPSS e indicadores KEV são sintéticos nesta tela. Na integração, serão enriquecidos por CVE em backend.')}`;
  }

  async function renderAdmin() {
    const users = await data.listUsers();
    const tenants = data.listTenants();
    if (!tenants.includes(state.priorityTenant)) state.priorityTenant = state.activeTenant;
    const priorityConfig = await data.getPriorityConfig(state.priorityTenant);
    const thresholdPercent = Number((priorityConfig.epssThreshold * 100).toFixed(1));
    const rows = users.filter((u) => !state.userQuery || `${u.name} ${u.email} ${u.role}`.toLowerCase().includes(state.userQuery.toLowerCase())).filter((u) => state.userStatus === 'all' || u.status.toLowerCase() === state.userStatus.toLowerCase());
    pageRoot.innerHTML = `
      ${pageHeading('Administração de acessos', 'Gerencie usuários e habilite somente os módulos autorizados para cada pessoa.', `<button class="primary-button" data-action="create-user"><span class="button-plus">＋</span>Novo usuário</button>`)}
      <section class="panel priority-config-panel"><div class="panel-heading"><div><h2 class="panel-title">Fórmula de priorização por tenant</h2><div class="panel-caption">O corte EPSS é isolado por tenant e aplicado ao dashboard, ativos e lista de vulnerabilidades.</div></div><span class="source-pill">Super admin</span></div>
        <form id="priorityConfigForm"><div class="priority-config-controls"><div class="form-group"><label for="priorityTenantSelect">Tenant da configuração</label><select id="priorityTenantSelect" name="tenantId" class="form-control" data-filter="priorityTenant">${tenants.map((tenant) => `<option value="${escapeHtml(tenant)}" ${tenant === state.priorityTenant ? 'selected' : ''}>${escapeHtml(tenant)}</option>`).join('')}</select></div><div class="form-group"><label for="epssThreshold">Limiar EPSS (%) · padrão 8,8%</label><input id="epssThreshold" name="epssThreshold" class="form-control" type="number" min="0" max="100" step="0.1" required value="${thresholdPercent}" /></div><div class="priority-save"><button class="primary-button" type="submit">Salvar fórmula</button></div></div>
          <div class="priority-rules"><div><b>KEV ativo</b><span>Consta no catálogo CISA e vem primeiro, mesmo com EPSS baixo.</span></div><div><b>KEV + EPSS ≥ ${String(thresholdPercent).replace('.', ',')}%</b><span>Destaque combinado para exploração conhecida e alta probabilidade.</span></div><div><b>EPSS ≥ ${String(thresholdPercent).replace('.', ',')}%</b><span>Sem KEV, entra depois dos itens KEV e ordena do maior para o menor.</span></div><div><b>EPSS ausente</b><span>Fica pendente e não vira score zero.</span></div></div>
          <p class="priority-config-note">CVSS/severidade e a marcação “Ativo crítico” continuam visíveis como contexto. Eles não alteram esta classificação. No protótipo, a configuração é salva neste navegador; gravação segura por tenant e auditoria serão feitas pelo backend/RLS do Supabase.</p>
        </form>
      </section>
      <div class="toolbar">
        <label class="search-field"><span>⌕</span><input data-filter="userQuery" value="${escapeHtml(state.userQuery)}" placeholder="Buscar usuário por nome ou e-mail" /></label>
        <select class="select-filter" data-filter="userStatus"><option value="all">Todos os status</option><option value="Ativo" ${state.userStatus === 'Ativo' ? 'selected' : ''}>Ativos</option><option value="Convidado" ${state.userStatus === 'Convidado' ? 'selected' : ''}>Convidados</option><option value="Desativado" ${state.userStatus === 'Desativado' ? 'selected' : ''}>Desativados</option></select>
        <span class="filter-count">${rows.length} usuários</span>
      </div>
      <section class="table-card"><div class="table-scroll"><table class="users-table"><thead><tr><th>Usuário</th><th>Perfil</th><th>Tenant</th><th>Módulos habilitados</th><th>Status</th><th>Ações</th></tr></thead><tbody>${rows.length ? rows.map((u) => `<tr><td><div class="user-identity"><span class="user-avatar">${initials(u.name)}</span><span>${escapeHtml(u.name)}<span class="sub-cell">${escapeHtml(u.email)}</span></span></div></td><td><span class="source-pill">${escapeHtml(u.role)}</span></td><td>${escapeHtml(u.tenant)}</td><td><div class="module-tags">${u.modules.slice(0, 4).map((m) => `<span class="module-tag">${escapeHtml(m)}</span>`).join('')}${u.modules.length > 4 ? `<span class="module-tag">+${u.modules.length - 4}</span>` : ''}</div></td><td>${statusPill(u.status)}</td><td><div class="row-actions"><button class="row-action" title="Editar permissões" data-user-edit="${u.id}">✎</button><button class="row-action ${u.status === 'Desativado' ? '' : 'danger'}" title="${u.status === 'Desativado' ? 'Reativar' : 'Desativar'} usuário" data-user-toggle="${u.id}" ${u.role === 'Super admin' ? 'disabled' : ''}>${u.status === 'Desativado' ? '↻' : '⊘'}</button></div></td></tr>`).join('') : emptyRow(6)}</tbody></table></div><div class="pagination"><span>Permissões aplicadas no servidor na versão integrada.</span><span>${rows.length} de ${users.length}</span></div></section>
      ${demoNotice('A criação e edição de usuários funciona apenas no navegador de demonstração; convites reais e controle de acesso server-side entram na integração Supabase.')}`;
  }

  async function renderPage() {
    const tenantSelect = document.getElementById('tenantSelect');
    if (tenantSelect) tenantSelect.value = state.activeTenant;
    const tenantBreadcrumb = document.querySelector('.breadcrumbs > span:first-child');
    if (tenantBreadcrumb) tenantBreadcrumb.textContent = state.activeTenant;
    document.getElementById('breadcrumbCurrent').textContent = titles[state.page];
    document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.page === state.page));
    const overview = await data.getOverview(state.activeTenant);
    const agentCount = document.querySelector('[data-page="agents"] .nav-count');
    const vulnerabilityCount = document.querySelector('[data-page="vulnerabilities"] .nav-count');
    if (agentCount) agentCount.textContent = number(overview.totalAgents);
    if (vulnerabilityCount) vulnerabilityCount.textContent = number(overview.totalVulnerabilities);
    if (state.page === 'overview') await renderOverview();
    if (state.page === 'agents') await renderAgents();
    if (state.page === 'vulnerabilities') await renderVulnerabilities();
    if (state.page === 'admin') await renderAdmin();
  }

  function toast(message) {
    const item = document.createElement('div');
    item.className = 'toast'; item.textContent = message; toastRoot.appendChild(item);
    setTimeout(() => item.remove(), 3200);
  }

  function openDrawer(content) {
    let root = document.getElementById('drawerRoot');
    if (!root) { root = document.createElement('div'); root.id = 'drawerRoot'; document.body.appendChild(root); }
    root.innerHTML = `<div class="drawer-backdrop" data-close-drawer><aside class="drawer" role="dialog" aria-modal="true">${content}</aside></div>`;
  }
  function closeDrawer() { const root = document.getElementById('drawerRoot'); if (root) root.remove(); }

  async function showFinding(id) {
    const f = await data.getFinding(id, state.activeTenant);
    if (!f) return;
    const users = await data.listUsers();
    const analystOptions = users.filter((u) => u.role !== 'Super admin' && u.status !== 'Desativado').map((u) => `<option ${f.assignee === u.name ? 'selected' : ''}>${escapeHtml(u.name)}</option>`).join('');
    const comments = f.comments.length ? f.comments.map((c) => `<div class="comment-item"><div class="comment-meta"><strong>${escapeHtml(c.author)}</strong><span>${dateShort(c.createdAt)}</span></div><p>${escapeHtml(c.text)}</p></div>`).join('') : '<div class="comment-item"><p>Nenhum comentário registrado.</p></div>';
    openDrawer(`
      <div class="drawer-header"><div><div class="eyebrow"><span class="eyebrow-mark"></span>Detalhe da vulnerabilidade</div><h2 class="drawer-title">${escapeHtml(f.cve)}</h2><div class="drawer-subtitle">${escapeHtml(f.title)}</div></div><button class="close-button" data-close-drawer aria-label="Fechar">×</button></div>
      <div class="drawer-section"><div class="detail-grid"><div class="detail-field"><label>Critério de priorização · ${escapeHtml(state.activeTenant)}</label><strong>${priorityBadge(f.priority)}</strong><span class="field-hint">${escapeHtml(f.priority.reason)}</span></div><div class="detail-field"><label>Severidade / CVSS · contexto</label><strong>${severityPill(f.severity)} &nbsp; ${f.cvss.toFixed(1)}</strong></div><div class="detail-field"><label>Estado da origem</label><strong>Presente no índice · DEMO</strong></div><div class="detail-field"><label>EPSS / percentil</label><strong>${Number.isFinite(f.epss) ? '<span class="epss-pill">' + percent(f.epss) + '</span> &nbsp; ' + percent(f.percentile / 100) : 'Score pendente'}</strong></div><div class="detail-field"><label>Exploração conhecida</label><strong>${f.kev ? '<span class="kev-pill">CISA KEV · KEV ativo</span>' : 'Não consta no KEV · DEMO'}</strong></div><div class="detail-field"><label>Criticidade do ativo · contexto</label><strong>${f.agentCritical ? 'Ativo crítico PUS' : 'Não crítico'}</strong></div></div></div>
      <div class="drawer-section"><h3 class="section-title">Ativo e software</h3><div class="detail-grid"><div class="detail-field"><label>Agent</label><strong>${escapeHtml(f.agent)} (${f.agentId})</strong></div><div class="detail-field"><label>IP</label><strong>${escapeHtml(f.ip)}</strong></div><div class="detail-field"><label>Pacote afetado</label><strong>${escapeHtml(f.package)}</strong></div><div class="detail-field"><label>Versão detectada</label><strong>${escapeHtml(f.version)}</strong></div><div class="detail-field"><label>Primeira detecção</label><strong>${escapeHtml(f.detectedAt)}</strong></div><div class="detail-field"><label>Fonte</label><strong>${escapeHtml(f.source)}</strong></div></div></div>
      <div class="drawer-section"><h3 class="section-title">Workflow de tratamento PUS</h3><div class="form-grid"><div class="form-group"><label for="findingStatus">Status</label><select class="workflow-select" id="findingStatus"><option ${f.status === 'Sem tratamento' ? 'selected' : ''}>Sem tratamento</option><option ${f.status === 'Atribuída' ? 'selected' : ''}>Atribuída</option><option ${f.status === 'Em correção' ? 'selected' : ''}>Em correção</option><option ${f.status === 'Correção aplicada' ? 'selected' : ''}>Correção aplicada</option><option ${f.status === 'Risco aceito' ? 'selected' : ''}>Risco aceito</option><option ${f.status === 'Falso positivo' ? 'selected' : ''}>Falso positivo</option></select></div><div class="form-group"><label for="findingAssignee">Responsável</label><select class="workflow-select" id="findingAssignee"><option>—</option>${analystOptions}</select></div><div class="form-group full"><label for="workflowReason">Justificativa (obrigatória para risco aceito/falso positivo)</label><input class="form-control" id="workflowReason" placeholder="Informe a justificativa de tratamento" /></div></div>
      <div class="comment-box"><textarea class="form-control" id="newComment" placeholder="Adicionar comentário de tratamento..."></textarea></div><div class="drawer-footer"><button class="secondary-button" data-close-drawer>Cancelar</button><button class="primary-button button-small" data-save-work="${f.id}">Salvar alterações</button></div></div>
      <div class="drawer-section"><h3 class="section-title">Comentários</h3><div class="comment-list" id="findingComments">${comments}</div></div>
      <div class="source-note">ⓘ Workflow e comentários são dados do PUS. A integração real manterá esses campos separados do estado de detecção Wazuh.</div>`);
  }

  async function showAgent(id) {
    const agent = await data.getAgent(id, state.activeTenant);
    if (!agent) return;
    openDrawer(`
      <div class="drawer-header"><div><div class="eyebrow"><span class="eyebrow-mark"></span>Ficha do ativo</div><h2 class="drawer-title">${escapeHtml(agent.name)}</h2><div class="drawer-subtitle">Agent ${agent.id} · ${escapeHtml(agent.group)}</div></div><button class="close-button" data-close-drawer aria-label="Fechar">×</button></div>
      <div class="drawer-section"><div class="detail-grid"><div class="detail-field"><label>Status de conexão</label><strong>${statusPill(agent.status)}</strong></div><div class="detail-field"><label>IP do agent</label><strong>${escapeHtml(agent.ip)}</strong></div><div class="detail-field"><label>Sistema operacional</label><strong>${escapeHtml(agent.os)}</strong></div><div class="detail-field"><label>Vulnerabilidades KEV ativo</label><strong>${number(agent.kevCount)}</strong></div><div class="detail-field"><label>Vulnerabilidades EPSS ≥ ${String((agent.priorityConfig.epssThreshold * 100).toFixed(1)).replace('.', ',')}%</label><strong>${number(agent.highEpssCount)}</strong></div><div class="detail-field"><label>Total de vulnerabilidades</label><strong>${agent.findings}</strong></div><div class="detail-field"><label>Último contato</label><strong>${escapeHtml(agent.lastKeepAlive)}</strong></div><div class="detail-field"><label>Último scan Syscollector</label><strong>${escapeHtml(agent.scanTime)}</strong></div></div></div>
      <div class="drawer-section"><div class="asset-criticality-control"><div><span class="section-title">Classificação do ativo</span><strong id="agentCriticalLabel">${agent.isCritical ? 'Ativo crítico' : 'Não crítico'}</strong><p>Marcação binária do PUS. Não adiciona pontos nem altera o score de risco.</p></div><label class="switch-control" aria-label="Marcar ${escapeHtml(agent.name)} como ativo crítico"><input type="checkbox" data-agent-critical="${agent.id}" ${agent.isCritical ? 'checked' : ''} /><span class="switch-track"></span></label></div><div class="source-note criticality-note">A alteração atualiza a classificação do ativo e seu contexto nas exposições associadas.</div></div>
      <div class="drawer-section"><h3 class="section-title">Exposição associada</h3><p class="page-subtitle">${agent.findings ? `${agent.findings} vulnerabilidades no conjunto demonstrativo.` : 'Sem vulnerabilidades no conjunto demonstrativo.'}</p><div style="margin-top:13px"><button class="secondary-button" data-agent-vulns="${agent.id}">Ver vulnerabilidades do agent →</button></div></div>
      <div class="source-note">Dados sintéticos. Na integração, o contato vem de <code>lastKeepAlive</code> e o scan é obtido do Syscollector.</div>`);
  }

  function openUserModal(user = null) {
    state.editingUser = user ? user.id : null;
    const modules = ['Visão geral', 'Ativos', 'Vulnerabilidades', 'Administração'];
    const selected = user ? user.modules : ['Visão geral', 'Ativos', 'Vulnerabilidades'];
    modalRoot.classList.remove('hidden');
    modalRoot.innerHTML = `<form class="modal" id="userForm"><div class="modal-title-row"><div><h2 class="modal-title">${user ? 'Editar acesso' : 'Convidar usuário'}</h2><p class="modal-copy">Defina o tenant e os módulos disponíveis para esta conta.</p></div><button class="close-button" type="button" data-close-modal>×</button></div>
      <div class="form-grid"><div class="form-group full"><label for="userName">Nome</label><input id="userName" name="name" class="form-control" required value="${escapeHtml(user?.name || '')}" placeholder="Nome completo" /></div><div class="form-group full"><label for="userEmail">E-mail corporativo</label><input id="userEmail" name="email" class="form-control" type="email" required value="${escapeHtml(user?.email || '')}" placeholder="nome@empresa.com" /></div><div class="form-group"><label for="userRole">Perfil</label><select id="userRole" name="role" class="form-control"><option ${user?.role === 'Analista' || !user ? 'selected' : ''}>Analista</option><option ${user?.role === 'Leitura' ? 'selected' : ''}>Leitura</option><option ${user?.role === 'Super admin' ? 'selected' : ''}>Super admin</option></select></div><div class="form-group"><label for="userTenant">Tenant</label><select id="userTenant" name="tenant" class="form-control"><option ${user?.tenant === 'PierSec' || !user ? 'selected' : ''}>PierSec</option><option ${user?.tenant === 'Empresa A' ? 'selected' : ''}>Empresa A</option><option ${user?.tenant === 'Empresa B' ? 'selected' : ''}>Empresa B</option></select></div></div>
      <div class="module-picker"><div class="section-title">Módulos acessíveis</div><div class="module-grid">${modules.map((m) => `<label class="module-option"><input type="checkbox" name="modules" value="${m}" ${selected.includes(m) ? 'checked' : ''} ${m === 'Administração' && user?.role === 'Super admin' ? 'checked' : ''} />${m}</label>`).join('')}</div></div>
      <div class="inline-demo-note"><strong>DEMO</strong><span>O convite será simulado neste navegador; nenhum e-mail será enviado.</span></div><div class="modal-actions"><button type="button" class="secondary-button" data-close-modal>Cancelar</button><button type="submit" class="primary-button">${user ? 'Salvar acesso' : 'Criar convite'}</button></div></form>`;
  }

  async function saveUserForm(form) {
    const wasEditing = Boolean(state.editingUser);
    const formData = new FormData(form);
    const user = {
      name: String(formData.get('name') || '').trim(), email: String(formData.get('email') || '').trim(),
      role: String(formData.get('role') || 'Analista'), tenant: String(formData.get('tenant') || 'PierSec'),
      modules: formData.getAll('modules'),
    };
    if (user.role === 'Super admin' && !user.modules.includes('Administração')) user.modules.push('Administração');
    if (state.editingUser) await data.updateUser(state.editingUser, user);
    else await data.createUser(user);
    modalRoot.classList.add('hidden'); modalRoot.innerHTML = ''; state.editingUser = null;
    toast(wasEditing ? 'Acesso atualizado (demonstração).' : 'Convite criado localmente (demonstração).');
    await renderPage();
  }

  document.body.addEventListener('click', async (event) => {
    const priorityNav = event.target.closest('[data-priority-nav]');
    if (priorityNav) {
      state.page = 'vulnerabilities'; state.vulnPriority = priorityNav.dataset.priorityNav;
      state.vulnQuery = ''; state.vulnSeverity = 'all'; state.vulnStatus = 'all'; state.vulnKev = 'all'; state.vulnMinEpss = '';
      closeDrawer(); await renderPage(); return;
    }
    const criticalAssetNav = event.target.closest('[data-agent-critical-nav]');
    if (criticalAssetNav) { state.page = 'agents'; state.agentCritical = criticalAssetNav.dataset.agentCriticalNav; closeDrawer(); modalRoot.classList.add('hidden'); await renderPage(); return; }
    const nav = event.target.closest('[data-page]');
    if (nav) { state.page = nav.dataset.page; closeDrawer(); modalRoot.classList.add('hidden'); document.getElementById('sidebar').classList.remove('open'); await renderPage(); return; }
    const action = event.target.closest('[data-action]')?.dataset.action;
    if (action === 'create-user') { openUserModal(); return; }
    if (action === 'refresh-demo') { await renderPage(); toast('Demonstração atualizada. Os dados permanecem sintéticos.'); return; }
    if (action === 'date-range') { toast('Filtro de período será ligado à origem de dados na integração.'); return; }
    if (event.target.closest('#helpButton')) { toast('PIER360 · protótipo funcional em ambiente local.'); return; }
    if (event.target.closest('#mobileMenu')) { document.getElementById('sidebar').classList.toggle('open'); return; }
    if (event.target.closest('#themeToggle')) { const root = document.documentElement; const next = root.dataset.theme === 'dark' ? 'light' : 'dark'; root.dataset.theme = next; localStorage.setItem('pier360-theme', next); document.getElementById('themeIcon').textContent = next === 'dark' ? '☼' : '☾'; return; }
    if (event.target.closest('[data-close-drawer]') && (!event.target.closest('.drawer') || event.target.closest('.close-button'))) { closeDrawer(); return; }
    if (event.target.closest('[data-close-modal]')) { modalRoot.classList.add('hidden'); modalRoot.innerHTML = ''; return; }
    const findingRow = event.target.closest('[data-finding]');
    if (findingRow) { await showFinding(findingRow.dataset.finding); return; }
    const agentRow = event.target.closest('[data-agent]');
    if (agentRow) { await showAgent(agentRow.dataset.agent); return; }
    const filterStatus = event.target.closest('[data-filter-status]');
    if (filterStatus) { state.vulnStatus = filterStatus.dataset.filterStatus; await renderVulnerabilities(); return; }
    const userEdit = event.target.closest('[data-user-edit]');
    if (userEdit) { const users = await data.listUsers(); openUserModal(users.find((u) => u.id === userEdit.dataset.userEdit)); return; }
    const userToggle = event.target.closest('[data-user-toggle]');
    if (userToggle) { const users = await data.listUsers(); const user = users.find((u) => u.id === userToggle.dataset.userToggle); if (user) { await data.updateUser(user.id, { status: user.status === 'Desativado' ? 'Ativo' : 'Desativado' }); toast(`Acesso de ${user.name} atualizado na demonstração.`); await renderAdmin(); } return; }
    const saveWork = event.target.closest('[data-save-work]');
    if (saveWork) {
      const status = document.getElementById('findingStatus').value;
      const assignee = document.getElementById('findingAssignee').value;
      const reason = document.getElementById('workflowReason').value.trim();
      if (['Risco aceito', 'Falso positivo'].includes(status) && !reason) { toast('Informe uma justificativa para este status.'); return; }
      const comment = document.getElementById('newComment').value.trim();
      await data.saveWorkItem(saveWork.dataset.saveWork, { status, assignee, reason }, state.activeTenant);
      if (comment) await data.addComment(saveWork.dataset.saveWork, comment, state.activeTenant);
      closeDrawer(); await renderPage(); toast('Workflow PUS atualizado na demonstração.'); return;
    }
    const agentVulns = event.target.closest('[data-agent-vulns]');
    if (agentVulns) { const agent = await data.getAgent(agentVulns.dataset.agentVulns, state.activeTenant); closeDrawer(); state.page = 'vulnerabilities'; state.vulnQuery = agent?.name || ''; state.vulnPriority = 'all'; await renderPage(); return; }
  });

  document.body.addEventListener('input', async (event) => {
    const filter = event.target.dataset.filter;
    if (!filter || !filter.endsWith('Query')) return;
    state[filter] = event.target.value;
    const marker = filter;
    const start = event.target.selectionStart;
    await renderPage();
    const nextInput = document.querySelector(`[data-filter="${marker}"]`);
    if (nextInput) { nextInput.focus(); nextInput.setSelectionRange(start, start); }
  });

  document.body.addEventListener('change', async (event) => {
    const tenantControl = event.target.closest('#tenantSelect');
    if (tenantControl) {
      state.activeTenant = await data.setActiveTenant(tenantControl.value);
      state.priorityTenant = state.activeTenant;
      state.agentQuery = ''; state.agentStatus = 'all'; state.agentPriority = 'all'; state.agentCritical = 'all';
      state.vulnQuery = ''; state.vulnSeverity = 'all'; state.vulnStatus = 'all'; state.vulnKev = 'all'; state.vulnMinEpss = ''; state.vulnPriority = 'all';
      closeDrawer(); modalRoot.classList.add('hidden'); await renderPage(); return;
    }
    const criticalAssetToggle = event.target.closest('[data-agent-critical]');
    if (criticalAssetToggle) {
      const updated = await data.setAgentCriticality(criticalAssetToggle.dataset.agentCritical, criticalAssetToggle.checked, state.activeTenant);
      if (updated) {
        const label = document.getElementById('agentCriticalLabel');
        if (label) label.textContent = updated.isCritical ? 'Ativo crítico' : 'Não crítico';
        await renderPage();
        toast(`${updated.name}: ${updated.isCritical ? 'marcado como ativo crítico' : 'removido da classificação de ativo crítico'} (demonstração).`);
      }
      return;
    }
    const filter = event.target.dataset.filter;
    if (!filter || filter.endsWith('Query')) return;
    state[filter] = event.target.value;
    await renderPage();
  });

  document.body.addEventListener('submit', async (event) => {
    if (event.target.id === 'priorityConfigForm') {
      event.preventDefault();
      const formData = new FormData(event.target);
      const thresholdPercent = Number(formData.get('epssThreshold'));
      const saved = await data.setPriorityConfig(state.priorityTenant, { epssThreshold: thresholdPercent / 100 });
      if (!saved) { toast('Informe um limiar EPSS entre 0% e 100%.'); return; }
      toast(`Limiar EPSS de ${state.priorityTenant} atualizado para ${String(thresholdPercent).replace('.', ',')}% na demonstração.`);
      await renderPage(); return;
    }
    if (event.target.id !== 'userForm') return;
    event.preventDefault();
    await saveUserForm(event.target);
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') { closeDrawer(); modalRoot.classList.add('hidden'); document.getElementById('sidebar').classList.remove('open'); }
  });

  const savedTheme = localStorage.getItem('pier360-theme');
  if (savedTheme === 'light' || savedTheme === 'dark') document.documentElement.dataset.theme = savedTheme;
  document.getElementById('themeIcon').textContent = document.documentElement.dataset.theme === 'dark' ? '☼' : '☾';
  renderPage();
})();
