import Link from "next/link";
import { redirect } from "next/navigation";
import { Brand } from "@/components/Brand";
import { requireAal2 } from "@/lib/auth/require-aal2";
import { listAccessibleTenants } from "@/lib/auth/tenant-access";
import { AuthorizationError, requireTenantModuleCapability } from "@/lib/auth/authorization";
import { findTenantIndexerConnection, readVulnerabilityPage, readVulnerabilitySummary, type VulnerabilityFinding, type VulnerabilitySeverity } from "@/lib/wazuh/vulnerabilities";
import { WazuhGatewayError } from "@/lib/wazuh/gateway";

export const dynamic = "force-dynamic";
type Search = Record<string, string | string[] | undefined>;
const severities: VulnerabilitySeverity[] = ["critical", "high", "medium", "low", "unknown"];

export default async function VulnerabilitiesPage({ searchParams }: { searchParams: Promise<Search> }) {
  const { claims, supabase } = await requireAal2();
  const userId = typeof claims.sub === "string" ? claims.sub : "";
  const params = await searchParams;
  const requestedTenantId = first(params.tenant);
  const search = (first(params.q) ?? "").trim().slice(0, 100);
  const requestedSeverity = first(params.severity) as VulnerabilitySeverity | undefined;
  const severity = requestedSeverity && severities.includes(requestedSeverity) ? requestedSeverity : undefined;
  const pageNumber = boundedInt(first(params.page), 1, 10_000, 1);
  const pageSize = 25;

  let tenants;
  try { tenants = await listAccessibleTenants(supabase, userId, "vulnerabilities"); }
  catch { redirect("/access-denied"); }
  if (!tenants.length) redirect("/access-denied");
  const tenant = requestedTenantId ? tenants.find((candidate) => candidate.id === requestedTenantId) : tenants[0];
  if (!tenant) redirect("/access-denied");
  try { await requireTenantModuleCapability({ tenantId: tenant.id, module: "vulnerabilities", capability: "read" }); }
  catch { redirect("/access-denied"); }

  let connection = null;
  let summary = null;
  let result = null;
  let integrationState: "not-configured" | "ready" | "error" = "not-configured";
  let errorMessage = "";
  let workItems: Record<string, { status: string; assignee_user_id: string | null }> = {};
  try {
    connection = await findTenantIndexerConnection(supabase, tenant.id);
    if (connection) {
      const offset = (pageNumber - 1) * pageSize;
      [summary, result] = await Promise.all([
        readVulnerabilitySummary(connection.connection_key),
        readVulnerabilityPage(connection.connection_key, { limit: pageSize, offset, search, severity }),
      ]);
      if (result.items.length) {
        const { data, error } = await supabase.from("vulnerability_work_items")
          .select("finding_key, status, assignee_user_id")
          .eq("tenant_id", tenant.id)
          .eq("source_connection_id", connection.id)
          .in("finding_key", result.items.map((item) => item.findingKey));
        if (error) throw new AuthorizationError(503, "vulnerability_workflow_unavailable");
        workItems = Object.fromEntries((data ?? []).map((item) => [item.finding_key, { status: item.status, assignee_user_id: item.assignee_user_id }]));
      }
      integrationState = "ready";
    }
  } catch (error) {
    integrationState = "error";
    errorMessage = describeError(error);
  }

  const filtered = severity || search ? result?.page.total ?? 0 : summary?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(filtered / pageSize));
  return (
    <main className="dashboard-shell assets-shell">
      <header className="dashboard-top">
        <Brand />
        <nav className="assets-nav" aria-label="Navegação principal">
          <Link href="/dashboard">Visão geral</Link>
          <Link href={`/assets?tenant=${tenant.id}`}>Ativos</Link>
          <Link aria-current="page" className="active" href={`/vulnerabilities?tenant=${tenant.id}`}>Vulnerabilidades</Link>
        </nav>
        <div className="account-chip">{typeof claims.email === "string" ? claims.email : "Sessão autenticada"}</div>
      </header>
      <section className="assets-content">
        <div className="assets-heading">
          <div><p className="eyebrow">Gestão de vulnerabilidades</p><h1>Vulnerabilidades</h1><p className="intro">Estado atual consultado no índice States do Wazuh para este tenant.</p></div>
          <form className="tenant-picker" method="get">
            <label htmlFor="vuln-tenant">Tenant</label>
            <select id="vuln-tenant" name="tenant" defaultValue={tenant.id}>{tenants.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
            <button className="secondary-button" type="submit">Abrir</button>
          </form>
        </div>
        {integrationState === "not-configured" ? <div className="integration-notice" role="status"><strong>Indexer ainda não conectado para {tenant.name}.</strong><p>O DEV não tem uma conexão Wazuh ativa. Nenhum dado fictício ou total zero é apresentado.</p></div> : null}
        {integrationState === "error" ? <div className="integration-error" role="alert"><strong>Não foi possível confirmar o estado atual das vulnerabilidades.</strong><p>{errorMessage} A página não interpreta falha ou resposta parcial como zero ou correção.</p></div> : null}
        {summary && result ? <>
          <div className="source-meta"><span className="source-ready"><i aria-hidden="true" /> Indexer · States · {connection?.display_name}</span><span>Consulta: {formatDate(summary.queriedAt)}</span></div>
          <div className="vulnerability-count-grid" aria-label="Vulnerabilidades por severidade">
            <SeverityCard title="Crítica" count={summary.severity.critical} tone="critical" />
            <SeverityCard title="Alta" count={summary.severity.high} tone="high" />
            <SeverityCard title="Média" count={summary.severity.medium} tone="medium" />
            <SeverityCard title="Baixa" count={summary.severity.low} tone="low" />
          </div>
          <section className="agent-list-panel">
            <div className="agent-list-heading"><div><h2>Inventário atual</h2><p>{filtered.toLocaleString("pt-BR")} vulnerabilidades neste resultado · workflow PUS separado do estado Wazuh</p></div>
              <form className="vulnerability-filters" method="get">
                <input type="hidden" name="tenant" value={tenant.id} />
                <label className="sr-only" htmlFor="vulnerability-search">Buscar CVE, pacote ou ativo</label>
                <input id="vulnerability-search" name="q" type="search" maxLength={100} defaultValue={search} placeholder="CVE, pacote ou ativo" />
                <label className="sr-only" htmlFor="vulnerability-severity">Filtrar severidade</label>
                <select id="vulnerability-severity" name="severity" defaultValue={severity ?? ""}><option value="">Todas as severidades</option><option value="critical">Crítica</option><option value="high">Alta</option><option value="medium">Média</option><option value="low">Baixa</option><option value="unknown">Não classificada</option></select>
                <button className="secondary-button" type="submit">Filtrar</button>
              </form>
            </div>
            {result.items.length ? <div className="agent-table-wrap"><table className="agent-table vulnerability-table"><thead><tr><th>CVE</th><th>Pacote / versão</th><th>Ativo</th><th>Severidade</th><th>CVSS</th><th>Detectada</th><th>Tratamento PUS</th></tr></thead><tbody>
              {result.items.map((finding) => <FindingRow key={finding.findingKey} finding={finding} workflow={workItems[finding.findingKey]?.status ?? "open"} />)}
            </tbody></table></div> : <p className="empty-state">Nenhuma vulnerabilidade encontrada com estes filtros.</p>}
            <div className="agent-pagination"><span>Página {pageNumber} de {totalPages}</span><div>{pageNumber > 1 ? <Link className="secondary-button" href={pageUrl(tenant.id, search, severity, pageNumber - 1)}>Anterior</Link> : null}{pageNumber < totalPages ? <Link className="secondary-button" href={pageUrl(tenant.id, search, severity, pageNumber + 1)}>Próxima</Link> : null}</div></div>
          </section>
          <p className="field-help">EPSS, KEV e priorização serão associados na próxima subfase de enriquecimento. A severidade e CVSS são contexto; não substituem a regra KEV → EPSS.</p>
        </> : null}
        <footer className="assets-footer"><Link className="text-link" href="/dashboard">Voltar à visão geral</Link></footer>
      </section>
    </main>
  );
}

function SeverityCard({ title, count, tone }: { title: string; count: number; tone: string }) { return <article className={`vulnerability-count-card ${tone}`}><span>{title}</span><strong>{count.toLocaleString("pt-BR")}</strong></article>; }
function FindingRow({ finding, workflow }: { finding: VulnerabilityFinding; workflow: string }) {
  const severityLabel = ({ critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa", unknown: "Não classificada" } as const)[finding.severity];
  return <tr><td><strong>{finding.cve ?? "CVE não informado"}</strong></td><td>{finding.packageName ?? "Pacote não informado"}<small>{finding.packageVersion ?? "Versão não informada"}</small></td><td>{finding.agentName ?? "Agent não informado"}<small>{finding.agentId ? `ID ${finding.agentId}` : finding.agentIp ?? "IP não informado"}</small></td><td><span className={`vulnerability-severity ${finding.severity}`}>{severityLabel}</span></td><td>{finding.cvssScore === null ? "—" : finding.cvssScore.toFixed(1)}</td><td>{formatDate(finding.detectedAt)}</td><td>{workflowLabel(workflow)}</td></tr>;
}
function first(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }
function boundedInt(value: string | undefined, min: number, max: number, fallback: number) { const parsed = Number.parseInt(value ?? "", 10); return Number.isFinite(parsed) ? Math.max(min, Math.min(max, parsed)) : fallback; }
function pageUrl(tenant: string, search: string, severity: VulnerabilitySeverity | undefined, page: number) { const query = new URLSearchParams({ tenant, page: String(page) }); if (search) query.set("q", search); if (severity) query.set("severity", severity); return `/vulnerabilities?${query}`; }
function formatDate(value: string | null) { if (!value) return "Sem registro"; const date = new Date(value); return Number.isFinite(date.getTime()) ? new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short", timeZone: "America/Sao_Paulo" }).format(date) : "Data inválida"; }
function workflowLabel(value: string) { return ({ open: "Sem tratamento", assigned: "Atribuída", in_progress: "Em correção", remediation_applied: "Correção aplicada", risk_accepted: "Risco aceito", false_positive: "Falso positivo" } as Record<string, string>)[value] ?? "Estado desconhecido"; }
function describeError(error: unknown) {
  if (error instanceof AuthorizationError && error.code === "wazuh_connection_lookup_unavailable") return "Não foi possível consultar a conexão autorizada deste tenant.";
  if (error instanceof AuthorizationError && error.code === "multiple_wazuh_connections_active") return "Há mais de uma conexão Wazuh ativa; a seleção precisa ser resolvida antes da consulta.";
  if (error instanceof AuthorizationError && error.code === "vulnerability_workflow_unavailable") return "O estado operacional do PUS não pôde ser consultado.";
  if (!(error instanceof WazuhGatewayError)) return "A consulta falhou por um erro inesperado.";
  switch (error.code) {
    case "gateway_not_configured": return "O endpoint do gateway ainda não foi configurado neste ambiente.";
    case "gateway_unavailable": return "O gateway Indexer está indisponível ou excedeu o tempo limite.";
    case "gateway_unauthorized": return "A autenticação entre o PIER360 e o gateway foi recusada.";
    case "gateway_rate_limited": return "O gateway limitou temporariamente a consulta.";
    case "source_auth_failed": return "A autenticação do gateway no Wazuh foi recusada.";
    case "gateway_invalid_response": return "A resposta do gateway não corresponde ao contrato esperado.";
    case "source_incomplete": return "A consulta ao States veio parcial e não representa o inventário completo.";
  }
}
