/*
 * Mock adapter for the platform-first prototype.
 * Replace this module with same-origin, authenticated BFF calls when integrating Wazuh.
 * Every record below is synthetic and must remain visibly marked as demo data.
 */
(function () {
  const agents = [
    { id: '001', name: 'srv-erp-prod-01', ip: '10.20.4.18', status: 'active', os: 'Ubuntu 22.04 LTS', lastKeepAlive: 'há 34 s', scanTime: 'há 11 min', isCritical: true, group: 'Linux / Produção' },
    { id: '002', name: 'db-core-prd-02', ip: '10.20.4.22', status: 'active', os: 'Windows Server 2022', lastKeepAlive: 'há 1 min', scanTime: 'há 18 min', group: 'Windows / Produção' },
    { id: '003', name: 'web-gateway-01', ip: '10.20.1.10', status: 'disconnected', os: 'Debian 12', lastKeepAlive: 'há 3 h 42 min', scanTime: 'há 4 h', group: 'Linux / DMZ' },
    { id: '004', name: 'adm-notebook-042', ip: '10.20.8.42', status: 'active', os: 'Windows 11 Pro', lastKeepAlive: 'há 2 min', scanTime: 'há 32 min', group: 'Endpoints / TI' },
    { id: '005', name: 'k8s-node-pool-03', ip: '10.20.6.33', status: 'active', os: 'Ubuntu 24.04 LTS', lastKeepAlive: 'há 45 s', scanTime: 'há 7 min', isCritical: true, group: 'Linux / Produção' },
    { id: '006', name: 'win-file-legacy-01', ip: '10.20.3.15', status: 'pending', os: 'Windows Server 2016', lastKeepAlive: 'Nunca conectado', scanTime: 'Sem scan', group: 'Windows / Legado' },
    { id: '007', name: 'api-worker-07', ip: '10.20.5.27', status: 'active', os: 'Rocky Linux 9.3', lastKeepAlive: 'há 26 s', scanTime: 'há 9 min', group: 'Linux / Aplicação' },
    { id: '008', name: 'backup-node-02', ip: '10.20.2.8', status: 'active', os: 'Red Hat Enterprise Linux 9', lastKeepAlive: 'há 58 s', scanTime: 'há 14 min', group: 'Linux / Infra' },
    { id: '009', name: 'vdi-pool-17', ip: '10.20.9.117', status: 'disconnected', os: 'Windows 10 Enterprise', lastKeepAlive: 'há 1 d 6 h', scanTime: 'há 1 d', group: 'Endpoints / VDI' },
    { id: '010', name: 'mon-agent-lab', ip: '10.20.12.61', status: 'active', os: 'Ubuntu 22.04 LTS', lastKeepAlive: 'há 17 s', scanTime: 'há 5 min', group: 'Linux / Laboratório' },
    { id: '011', name: 'mac-design-08', ip: '10.20.10.8', status: 'pending', os: 'macOS 14.5', lastKeepAlive: 'Nunca conectado', scanTime: 'Sem scan', group: 'Endpoints / Design' },
    { id: '012', name: 'crm-app-01', ip: '10.20.4.35', status: 'active', os: 'Windows Server 2019', lastKeepAlive: 'há 49 s', scanTime: 'há 22 min', group: 'Windows / Produção' },
  ];

  const TENANTS = ['PierSec', 'Empresa A', 'Empresa B'];
  const SOURCE_TENANT = 'PierSec';
  const DEFAULT_PRIORITY_CONFIG = { epssThreshold: 0.088 };

  const findings = [
    { id: 'finding-001', cve: 'CVE-2024-3094', title: 'XZ Utils backdoor', severity: 'Crítica', cvss: 10.0, epss: .9724, percentile: 99.9, kev: true, package: 'xz-utils', version: '5.6.1', agentId: '001', agent: 'srv-erp-prod-01', ip: '10.20.4.18', detectedAt: 'há 2 h', status: 'Em correção', assignee: 'Marina Costa', source: 'Wazuh States · Demo' },
    { id: 'finding-002', cve: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset', severity: 'Alta', cvss: 7.5, epss: .8841, percentile: 99.2, kev: true, package: 'nginx', version: '1.24.0', agentId: '005', agent: 'k8s-node-pool-03', ip: '10.20.6.33', detectedAt: 'há 5 h', status: 'Atribuída', assignee: 'Rafael Lima', source: 'Wazuh States · Demo' },
    { id: 'finding-003', cve: 'CVE-2024-21626', title: 'runc container escape', severity: 'Crítica', cvss: 8.6, epss: .5918, percentile: 97.1, kev: true, package: 'runc', version: '1.1.11', agentId: '005', agent: 'k8s-node-pool-03', ip: '10.20.6.33', detectedAt: 'há 1 d', status: 'Sem tratamento', assignee: '—', source: 'Wazuh States · Demo' },
    { id: 'finding-004', cve: 'CVE-2024-3400', title: 'PAN-OS command injection', severity: 'Crítica', cvss: 10.0, epss: .6442, percentile: 98.1, kev: true, package: 'pan-os', version: '11.1.2', agentId: '003', agent: 'web-gateway-01', ip: '10.20.1.10', detectedAt: 'há 2 d', status: 'Atribuída', assignee: 'Bruno Alves', source: 'Wazuh States · Demo' },
    { id: 'finding-005', cve: 'CVE-2024-6387', title: 'OpenSSH signal handler race', severity: 'Alta', cvss: 8.1, epss: .7345, percentile: 98.6, kev: true, package: 'openssh-server', version: '9.6p1', agentId: '007', agent: 'api-worker-07', ip: '10.20.5.27', detectedAt: 'há 3 d', status: 'Em correção', assignee: 'Marina Costa', source: 'Wazuh States · Demo' },
    { id: 'finding-006', cve: 'CVE-2024-38063', title: 'Windows TCP/IP remote code execution', severity: 'Crítica', cvss: 9.8, epss: .8122, percentile: 99.1, kev: false, package: 'Windows TCP/IP', version: '10.0.20348', agentId: '002', agent: 'db-core-prd-02', ip: '10.20.4.22', detectedAt: 'há 4 d', status: 'Sem tratamento', assignee: '—', source: 'Wazuh States · Demo' },
    { id: 'finding-007', cve: 'CVE-2023-48795', title: 'SSH Terrapin prefix truncation', severity: 'Média', cvss: 5.9, epss: .0421, percentile: 83.7, kev: false, package: 'libssh', version: '0.10.5', agentId: '008', agent: 'backup-node-02', ip: '10.20.2.8', detectedAt: 'há 6 d', status: 'Correção aplicada', assignee: 'Rafael Lima', source: 'Wazuh States · Demo' },
    { id: 'finding-008', cve: 'CVE-2024-27322', title: 'Apache HTTP Server request smuggling', severity: 'Alta', cvss: 8.2, epss: .1865, percentile: 94.1, kev: false, package: 'httpd', version: '2.4.58', agentId: '012', agent: 'crm-app-01', ip: '10.20.4.35', detectedAt: 'há 1 sem', status: 'Risco aceito', assignee: 'Camila Rocha', source: 'Wazuh States · Demo' },
    { id: 'finding-009', cve: 'CVE-2023-38545', title: 'curl SOCKS5 heap buffer overflow', severity: 'Alta', cvss: 8.8, epss: .0287, percentile: 76.5, kev: false, package: 'curl', version: '8.3.0', agentId: '001', agent: 'srv-erp-prod-01', ip: '10.20.4.18', detectedAt: 'há 1 sem', status: 'Sem tratamento', assignee: '—', source: 'Wazuh States · Demo' },
    { id: 'finding-010', cve: 'CVE-2024-3094', title: 'XZ Utils backdoor', severity: 'Crítica', cvss: 10.0, epss: .9724, percentile: 99.9, kev: true, package: 'xz-utils', version: '5.6.1', agentId: '008', agent: 'backup-node-02', ip: '10.20.2.8', detectedAt: 'há 2 h', status: 'Sem tratamento', assignee: '—', source: 'Wazuh States · Demo' },
    { id: 'finding-011', cve: 'CVE-2024-3094', title: 'XZ Utils backdoor', severity: 'Crítica', cvss: 10.0, epss: .9724, percentile: 99.9, kev: true, package: 'xz-utils', version: '5.6.1', agentId: '010', agent: 'mon-agent-lab', ip: '10.20.12.61', detectedAt: 'há 2 h', status: 'Falso positivo', assignee: 'David Basile', source: 'Wazuh States · Demo' },
  ];

  const seedUsers = [
    { id: 'user-001', name: 'David Basile', email: 'david.basile@piersec.com.br', role: 'Super admin', tenant: 'PierSec', status: 'Ativo', modules: ['Visão geral', 'Ativos', 'Vulnerabilidades', 'Administração'] },
    { id: 'user-002', name: 'Marina Costa', email: 'marina.costa@piersec.com.br', role: 'Analista', tenant: 'PierSec', status: 'Ativo', modules: ['Visão geral', 'Ativos', 'Vulnerabilidades'] },
    { id: 'user-003', name: 'Rafael Lima', email: 'rafael.lima@piersec.com.br', role: 'Analista', tenant: 'PierSec', status: 'Ativo', modules: ['Visão geral', 'Vulnerabilidades'] },
    { id: 'user-004', name: 'Camila Rocha', email: 'camila.rocha@piersec.com.br', role: 'Leitura', tenant: 'PierSec', status: 'Convidado', modules: ['Visão geral', 'Ativos', 'Vulnerabilidades'] },
  ];

  const memory = {
    users: load('pier360-demo-users', seedUsers),
    work: load('pier360-demo-work', {}),
    comments: load('pier360-demo-comments', {}),
    assetCriticality: load('pier360-demo-asset-criticality', {}),
    priorityConfigs: load('pier360-demo-priority-configs', {}),
    activeTenant: load('pier360-demo-active-tenant', SOURCE_TENANT),
  };

  function load(key, fallback) {
    try {
      const value = localStorage.getItem(key);
      return value ? JSON.parse(value) : JSON.parse(JSON.stringify(fallback));
    } catch (_) {
      return JSON.parse(JSON.stringify(fallback));
    }
  }

  function persist(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) { /* Storage optional in demo */ }
  }

  function workKey(tenantId, id) { return `${tenantId}:${id}`; }

  function workFor(finding, tenantId) {
    const key = workKey(tenantId, finding.id);
    return Object.assign({ status: finding.status, assignee: finding.assignee }, memory.work[key] || (tenantId === SOURCE_TENANT ? memory.work[finding.id] : {}) || {});
  }

  function isCriticalAsset(agent, tenantId) {
    const key = `${tenantId}:${agent.id}`;
    if (Object.prototype.hasOwnProperty.call(memory.assetCriticality, key)) return memory.assetCriticality[key] === true;
    return tenantId === SOURCE_TENANT && Object.prototype.hasOwnProperty.call(memory.assetCriticality, agent.id)
      ? memory.assetCriticality[agent.id] === true
      : Boolean(agent.isCritical);
  }

  function tenantAgents(tenantId) { return tenantId === SOURCE_TENANT ? agents : []; }
  function tenantFindings(tenantId) { return tenantId === SOURCE_TENANT ? findings : []; }

  function priorityConfig(tenantId) {
    const saved = memory.priorityConfigs[tenantId] || {};
    const threshold = Number(saved.epssThreshold);
    return { epssThreshold: Number.isFinite(threshold) && threshold >= 0 && threshold <= 1 ? threshold : DEFAULT_PRIORITY_CONFIG.epssThreshold };
  }

  function classifyPriority(finding, config) {
    const hasEpss = typeof finding.epss === 'number' && Number.isFinite(finding.epss);
    const aboveThreshold = hasEpss && finding.epss >= config.epssThreshold;
    const thresholdLabel = `${(config.epssThreshold * 100).toFixed(1).replace('.', ',')}%`;
    if (finding.kev) {
      return {
        key: 'kev', rank: 1,
        label: aboveThreshold ? `KEV ATIVO + EPSS ≥ ${thresholdLabel}` : 'KEV ATIVO',
        reason: aboveThreshold
          ? `Exploração ativa confirmada no CISA KEV e EPSS igual ou superior a ${thresholdLabel}.`
          : 'Exploração ativa confirmada no catálogo CISA KEV; precede o EPSS.',
      };
    }
    if (aboveThreshold) {
      return { key: 'epss_high', rank: 2, label: `EPSS ≥ ${thresholdLabel}`, reason: `EPSS igual ou superior ao corte de ${thresholdLabel}.` };
    }
    if (hasEpss) return { key: 'epss_below', rank: 3, label: `EPSS < ${thresholdLabel}`, reason: `EPSS abaixo do corte de ${thresholdLabel}.` };
    return { key: 'pending', rank: 4, label: 'EPSS pendente', reason: 'Sem score EPSS válido; não interpretar ausência como zero.' };
  }

  function findingView(finding, tenantId) {
    const config = priorityConfig(tenantId);
    const asset = tenantAgents(tenantId).find((agent) => agent.id === finding.agentId);
    return Object.assign({}, finding, workFor(finding, tenantId), {
      priority: classifyPriority(finding, config),
      agentCritical: asset ? isCriticalAsset(asset, tenantId) : false,
      priorityConfig: config,
    });
  }

  function agentView(agent, tenantId) {
    const config = priorityConfig(tenantId);
    const agentFindings = tenantFindings(tenantId).filter((finding) => finding.agentId === agent.id).map((finding) => findingView(finding, tenantId));
    return Object.assign({}, agent, {
      isCritical: isCriticalAsset(agent, tenantId),
      priorityConfig: config,
      findings: agentFindings.length,
      kevCount: agentFindings.filter((finding) => finding.priority.key === 'kev').length,
      highEpssCount: agentFindings.filter((finding) => typeof finding.epss === 'number' && Number.isFinite(finding.epss) && finding.epss >= config.epssThreshold).length,
      priorityCount: agentFindings.filter((finding) => ['kev', 'epss_high'].includes(finding.priority.key)).length,
    });
  }

  function sortByPriority(rows) {
    return rows.sort((a, b) => a.priority.rank - b.priority.rank
      || (Number.isFinite(b.epss) ? b.epss : -1) - (Number.isFinite(a.epss) ? a.epss : -1)
      || a.cve.localeCompare(b.cve)
      || a.agent.localeCompare(b.agent));
  }

  window.PIER360Data = {
    source: 'demo',
    listTenants() { return TENANTS.slice(); },
    getActiveTenant() { return TENANTS.includes(memory.activeTenant) ? memory.activeTenant : SOURCE_TENANT; },
    async setActiveTenant(tenantId) {
      if (!TENANTS.includes(tenantId)) return this.getActiveTenant();
      memory.activeTenant = tenantId;
      persist('pier360-demo-active-tenant', tenantId);
      return tenantId;
    },
    async getPriorityConfig(tenantId = SOURCE_TENANT) { return priorityConfig(tenantId); },
    async setPriorityConfig(tenantId, patch) {
      const threshold = Number(patch?.epssThreshold);
      if (!TENANTS.includes(tenantId) || !Number.isFinite(threshold) || threshold < 0 || threshold > 1) return null;
      memory.priorityConfigs[tenantId] = { epssThreshold: threshold };
      persist('pier360-demo-priority-configs', memory.priorityConfigs);
      return priorityConfig(tenantId);
    },
    async getOverview(tenantId = SOURCE_TENANT) {
      const tenantAssetRows = tenantAgents(tenantId).map((agent) => agentView(agent, tenantId));
      const tenantFindingRows = sortByPriority(tenantFindings(tenantId).map((finding) => findingView(finding, tenantId)));
      const criticalAgentIds = new Set(tenantAssetRows.filter((agent) => agent.isCritical).map((agent) => agent.id));
      const config = priorityConfig(tenantId);
      const hasHighEpss = (finding) => typeof finding.epss === 'number' && Number.isFinite(finding.epss) && finding.epss >= config.epssThreshold;
      const priorityRows = tenantFindingRows.filter((finding) => ['kev', 'epss_high'].includes(finding.priority.key));
      const countSeverity = (severity) => tenantFindingRows.filter((finding) => finding.severity === severity).length;
      return {
        totalAgents: tenantAssetRows.length,
        activeAgents: tenantAssetRows.filter((agent) => agent.status === 'active').length,
        disconnectedAgents: tenantAssetRows.filter((agent) => agent.status === 'disconnected').length,
        pendingAgents: tenantAssetRows.filter((agent) => agent.status === 'pending').length,
        openFindings: tenantFindingRows.length,
        critical: countSeverity('Crítica'), high: countSeverity('Alta'), medium: countSeverity('Média'), low: countSeverity('Baixa'),
        kevActive: tenantFindingRows.filter((finding) => finding.kev).length,
        kevAndHighEpss: tenantFindingRows.filter((finding) => finding.kev && hasHighEpss(finding)).length,
        highEpss: tenantFindingRows.filter(hasHighEpss).length,
        belowEpss: tenantFindingRows.filter((finding) => finding.priority.key === 'epss_below').length,
        missingEpss: tenantFindingRows.filter((finding) => finding.priority.key === 'pending').length,
        priorityAffectedAssets: new Set(priorityRows.map((finding) => finding.agentId)).size,
        queriedAt: new Date().toISOString(), criticalAssets: tenantAssetRows.filter((agent) => agent.isCritical).length,
        criticalAssetVulnerabilities: tenantFindingRows.filter((finding) => criticalAgentIds.has(finding.agentId)).length,
        correctedLast30Days: tenantFindingRows.filter((finding) => finding.status === 'Correção aplicada'
          && Number.isFinite(Date.parse(finding.updatedAt))
          && Date.now() - Date.parse(finding.updatedAt) <= 30 * 24 * 60 * 60 * 1000).length,
        totalVulnerabilities: tenantFindingRows.length, demoAssetCount: tenantAssetRows.length,
        priorityConfig: priorityConfig(tenantId),
        trend: tenantFindingRows.length ? [
          { month: '03', critical: 2, high: 3, medium: 2, low: 1 },
          { month: '04', critical: 5, high: 6, medium: 6, low: 0 },
          { month: '05', critical: 38, high: 40, medium: 28, low: 0 },
          { month: '06', critical: 4, high: 5, medium: 6, low: 5 },
          { month: '07', critical: 5, high: 6, medium: 7, low: 7 },
        ] : [],
      };
    },
    async listAgents(filters = {}) {
      const tenantId = filters.tenantId || SOURCE_TENANT;
      let rows = tenantAgents(tenantId).map((agent) => agentView(agent, tenantId));
      if (filters.query) {
        const q = filters.query.toLowerCase();
        rows = rows.filter((a) => `${a.name} ${a.ip} ${a.os} ${a.id}`.toLowerCase().includes(q));
      }
      if (filters.status && filters.status !== 'all') {
        rows = rows.filter((a) => filters.status === 'pending' ? a.status === 'pending' : a.status === filters.status);
      }
      if (filters.priority === 'kev') rows = rows.filter((agent) => agent.kevCount > 0);
      if (filters.priority === 'epss_high') rows = rows.filter((agent) => agent.highEpssCount > 0);
      if (filters.critical === 'yes') rows = rows.filter((a) => a.isCritical);
      if (filters.critical === 'no') rows = rows.filter((a) => !a.isCritical);
      return rows;
    },
    async getAgent(id, tenantId = SOURCE_TENANT) { const agent = tenantAgents(tenantId).find((a) => a.id === id); return agent ? agentView(agent, tenantId) : null; },
    async setAgentCriticality(id, isCritical, tenantId = SOURCE_TENANT) {
      if (typeof isCritical !== 'boolean' || !tenantAgents(tenantId).some((agent) => agent.id === id)) return null;
      memory.assetCriticality[`${tenantId}:${id}`] = isCritical;
      persist('pier360-demo-asset-criticality', memory.assetCriticality);
      return this.getAgent(id, tenantId);
    },
    async listFindings(filters = {}) {
      const tenantId = filters.tenantId || SOURCE_TENANT;
      let rows = tenantFindings(tenantId).map((finding) => findingView(finding, tenantId));
      if (filters.query) {
        const q = filters.query.toLowerCase();
        rows = rows.filter((f) => `${f.cve} ${f.title} ${f.package} ${f.agent}`.toLowerCase().includes(q));
      }
      if (filters.severity && filters.severity !== 'all') rows = rows.filter((f) => f.severity.toLowerCase() === filters.severity.toLowerCase());
      if (filters.status && filters.status !== 'all') rows = rows.filter((f) => f.status === filters.status);
      if (filters.kev === 'yes') rows = rows.filter((f) => f.kev);
      if (filters.kev === 'no') rows = rows.filter((f) => !f.kev);
      if (filters.minEpss) rows = rows.filter((f) => typeof f.epss === 'number' && Number.isFinite(f.epss) && f.epss >= Number(filters.minEpss));
      if (filters.priority && filters.priority !== 'all') {
        const config = priorityConfig(tenantId);
        const aboveThreshold = (finding) => typeof finding.epss === 'number' && Number.isFinite(finding.epss) && finding.epss >= config.epssThreshold;
        if (filters.priority === 'kev') rows = rows.filter((finding) => finding.kev);
        else if (filters.priority === 'kev_epss_high') rows = rows.filter((finding) => finding.kev && aboveThreshold(finding));
        else if (filters.priority === 'epss_high') rows = rows.filter(aboveThreshold);
        else if (filters.priority === 'epss_below') rows = rows.filter((finding) => !finding.kev && finding.priority.key === 'epss_below');
        else rows = rows.filter((finding) => finding.priority.key === 'pending');
      }
      return sortByPriority(rows);
    },
    async getFinding(id, tenantId = SOURCE_TENANT) {
      const finding = tenantFindings(tenantId).find((f) => f.id === id);
      if (!finding) return null;
      const key = workKey(tenantId, id);
      return Object.assign(findingView(finding, tenantId), { comments: memory.comments[key] || (tenantId === SOURCE_TENANT ? memory.comments[id] : []) || [] });
    },
    async saveWorkItem(id, patch, tenantId = SOURCE_TENANT) {
      const key = workKey(tenantId, id);
      memory.work[key] = Object.assign({}, memory.work[key] || {}, patch, { updatedAt: new Date().toISOString() });
      persist('pier360-demo-work', memory.work);
      return this.getFinding(id, tenantId);
    },
    async addComment(id, text, tenantId = SOURCE_TENANT, author = 'David Basile') {
      const key = workKey(tenantId, id);
      const list = memory.comments[key] || [];
      list.unshift({ id: `comment-${Date.now()}`, text, author, createdAt: new Date().toISOString() });
      memory.comments[key] = list;
      persist('pier360-demo-comments', memory.comments);
      return list;
    },
    async listUsers() { return memory.users.slice(); },
    async createUser(user) {
      const created = Object.assign({ id: `user-${Date.now()}`, role: 'Analista', tenant: 'PierSec', status: 'Convidado' }, user);
      memory.users.unshift(created);
      persist('pier360-demo-users', memory.users);
      return created;
    },
    async updateUser(id, patch) {
      memory.users = memory.users.map((u) => u.id === id ? Object.assign({}, u, patch) : u);
      persist('pier360-demo-users', memory.users);
      return memory.users.find((u) => u.id === id) || null;
    },
  };
})();
