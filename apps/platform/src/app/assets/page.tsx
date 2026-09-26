import Link from "next/link";
import { redirect } from "next/navigation";
import { Brand } from "@/components/Brand";
import { requireAal2 } from "@/lib/auth/require-aal2";
import { listAccessibleTenants } from "@/lib/auth/tenant-access";
import { AuthorizationError, requireTenantModuleCapability } from "@/lib/auth/authorization";
import {
  findTenantWazuhConnection,
  readAgentPage,
  readAgentSummary,
  type AgentListResponse,
  type AgentSummaryResponse,
} from "@/lib/wazuh/agents";
import { WazuhGatewayError } from "@/lib/wazuh/gateway";

export const dynamic = "force-dynamic";

type Search = Record<string, string | string[] | undefined>;

export default async function AssetsPage({ searchParams }: { searchParams: Promise<Search> }) {
  const { claims, supabase } = await requireAal2();
  const userId = typeof claims.sub === "string" ? claims.sub : "";
  const params = await searchParams;
  const requestedTenantId = first(params.tenant);
  const search = (first(params.q) ?? "").trim().slice(0, 100);
  const pageNumber = boundedInt(first(params.page), 1, 10_000, 1);
  const pageSize = 25;

  let tenants;
  try {
    tenants = await listAccessibleTenants(supabase, userId, "assets");
  } catch {
    redirect("/access-denied");
  }
  if (!tenants.length) redirect("/access-denied");

  const tenant = requestedTenantId
    ? tenants.find((candidate) => candidate.id === requestedTenantId)
    : tenants[0];
  if (!tenant) redirect("/access-denied");

  try {
    await requireTenantModuleCapability({ tenantId: tenant.id, module: "assets", capability: "read" });
  } catch {
    redirect("/access-denied");
  }

  let connection = null;
  let summary: AgentSummaryResponse | null = null;
  let result: AgentListResponse | null = null;
  let integrationState: "not-configured" | "ready" | "error" = "not-configured";
  let errorMessage = "";

  try {
    connection = await findTenantWazuhConnection(supabase, tenant.id);
    if (connection) {
      const offset = (pageNumber - 1) * pageSize;
      [summary, result] = await Promise.all([
        readAgentSummary(connection.connection_key),
        readAgentPage(connection.connection_key, { limit: pageSize, offset, search }),
      ]);
      integrationState = "ready";
    }
  } catch (error) {
    integrationState = "error";
    errorMessage = describeWazuhError(error);
  }

  const totalPages = Math.max(1, Math.ceil((result?.page.total ?? 0) / pageSize));
  const previousUrl = pageNumber > 1 ? assetsUrl(tenant.id, search, pageNumber - 1) : null;
  const nextUrl = result && pageNumber < totalPages ? assetsUrl(tenant.id, search, pageNumber + 1) : null;

  return (
    <main className="dashboard-shell assets-shell">
      <header className="dashboard-top">
        <Brand />
        <nav className="assets-nav" aria-label="Navegação principal">
          <Link href="/dashboard">Visão geral</Link>
          <Link aria-current="page" className="active" href={`/assets?tenant=${tenant.id}`}>Ativos</Link>
          <Link href={`/vulnerabilities?tenant=${tenant.id}`}>Vulnerabilidades</Link>
        </nav>
        <div className="account-chip">{typeof claims.email === "string" ? claims.email : "Sessão autenticada"}</div>
      </header>

      <section className="assets-content">
        <div className="assets-heading">
          <div>
            <p className="eyebrow">Inventário de agentes</p>
            <h1>Ativos</h1>
            <p className="intro">Status, contato e inventário Syscollector consultados na Manager API do Wazuh.</p>
          </div>
          <form className="tenant-picker" method="get">
            <label htmlFor="tenant-picker">Tenant</label>
            <select id="tenant-picker" name="tenant" defaultValue={tenant.id}>
              {tenants.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
            <button className="secondary-button" type="submit">Abrir</button>
          </form>
        </div>

        {integrationState === "not-configured" ? (
          <div className="integration-notice" role="status">
            <strong>Integração Wazuh ainda não configurada para {tenant.name}.</strong>
            <p>O DEV não tem uma conexão Manager ativa cadastrada. Nenhum dado DEMO ou total zero será apresentado como dado real.</p>
          </div>
        ) : null}
        {integrationState === "error" ? (
          <div className="integration-error" role="alert">
            <strong>Não foi possível confirmar os dados atuais dos agentes.</strong>
            <p>{errorMessage} A página não substituiu a falha por contagens zero.</p>
          </div>
        ) : null}

        {summary && result ? (
          <>
            <div className="source-meta">
              <span className="source-ready"><i aria-hidden="true" /> Manager API conectada · {connection?.display_name}</span>
              <span>Consulta: {formatDate(summary.queriedAt)}</span>
            </div>
            <div className="agent-count-grid" aria-label="Distribuição de agentes">
              <StatusCard title="Total de agents" count={summary.status.total} />
              <StatusCard title="Ativos" count={summary.status.active} tone="green" />
              <StatusCard title="Desconectados" count={summary.status.disconnected} tone="amber" />
              <StatusCard title="Pendentes" count={summary.status.pending + summary.status.neverConnected} tone="purple" />
            </div>
            {summary.status.other ? <p className="field-help">{summary.status.other} agent(s) vieram em estado Wazuh ainda não mapeado para os três grupos da V1.</p> : null}

            <section className="agent-list-panel">
              <div className="agent-list-heading">
                <div>
                  <h2>Agentes Wazuh</h2>
                  <p>{result.page.total.toLocaleString("pt-BR")} agentes no resultado atual</p>
                </div>
                <form className="agent-search" method="get">
                  <input type="hidden" name="tenant" value={tenant.id} />
                  <label className="sr-only" htmlFor="agent-search">Buscar por nome, IP ou ID</label>
                  <input id="agent-search" name="q" type="search" maxLength={100} defaultValue={search} placeholder="Buscar nome, IP ou ID" />
                  <button className="secondary-button" type="submit">Buscar</button>
                </form>
              </div>
              {result.items.length ? (
                <div className="agent-table-wrap">
                  <table className="agent-table">
                    <thead><tr><th>Agent</th><th>IP</th><th>Status</th><th>Último contato</th><th></th></tr></thead>
                    <tbody>
                      {result.items.map((agent) => (
                        <tr key={agent.id}>
                          <td><strong>{agent.name}</strong><small>ID {agent.id}{agent.osName ? ` · ${agent.osName}${agent.osVersion ? ` ${agent.osVersion}` : ""}` : ""}</small></td>
                          <td>{agent.ip ?? "Não informado"}</td>
                          <td><span className={`agent-status ${statusTone(agent.rawStatus)}`}>{statusLabel(agent.rawStatus)}</span></td>
                          <td>{formatDate(agent.lastKeepAlive)}</td>
                          <td><Link className="text-link" href={`/assets/${encodeURIComponent(agent.id)}?tenant=${tenant.id}`}>Detalhes</Link></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : <p className="empty-state">Nenhum agente encontrado com este filtro.</p>}
              <div className="agent-pagination">
                <span>Página {pageNumber} de {totalPages}</span>
                <div>
                  {previousUrl ? <Link className="secondary-button" href={previousUrl}>Anterior</Link> : null}
                  {nextUrl ? <Link className="secondary-button" href={nextUrl}>Próxima</Link> : null}
                </div>
              </div>
            </section>
          </>
        ) : null}

        <footer className="assets-footer"><Link className="text-link" href="/dashboard">Voltar à visão geral</Link></footer>
      </section>
    </main>
  );
}

function StatusCard({ title, count, tone = "blue" }: { title: string; count: number; tone?: string }) {
  return <article className={`agent-count-card ${tone}`}><span>{title}</span><strong>{count.toLocaleString("pt-BR")}</strong></article>;
}

function first(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

function boundedInt(value: string | undefined, min: number, max: number, fallback: number) {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) ? Math.max(min, Math.min(max, parsed)) : fallback;
}

function assetsUrl(tenantId: string, search: string, page: number) {
  const params = new URLSearchParams({ tenant: tenantId, page: String(page) });
  if (search) params.set("q", search);
  return `/assets?${params.toString()}`;
}

function statusLabel(status: string) {
  switch (status) {
    case "active": return "Ativo";
    case "disconnected": return "Desconectado";
    case "pending":
    case "never_connected": return "Pendente";
    default: return status || "Desconhecido";
  }
}

function statusTone(status: string) {
  if (status === "active") return "active";
  if (status === "disconnected") return "disconnected";
  return "pending";
}

function formatDate(value: string | null) {
  if (!value) return "Sem registro";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Data inválida";
  return new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short", timeZone: "America/Sao_Paulo" }).format(date);
}

function describeWazuhError(error: unknown) {
  if (error instanceof AuthorizationError && error.code === "wazuh_connection_lookup_unavailable") {
    return "Não foi possível consultar a configuração autorizada do tenant.";
  }
  if (error instanceof AuthorizationError && error.code === "multiple_wazuh_connections_active") {
    return "Há mais de uma conexão Manager ativa para este tenant; a seleção precisa ser configurada antes da leitura.";
  }
  if (!(error instanceof WazuhGatewayError)) return "A consulta falhou por um erro inesperado.";
  switch (error.code) {
    case "gateway_not_configured": return "O endpoint de leitura ainda não foi configurado no ambiente DEV.";
    case "gateway_unavailable": return "O gateway de leitura está indisponível ou excedeu o tempo limite.";
    case "gateway_unauthorized": return "A autenticação entre o PIER360 e o gateway foi recusada.";
    case "gateway_rate_limited": return "O gateway limitou temporariamente as consultas.";
    case "gateway_invalid_response": return "O gateway respondeu fora do contrato esperado.";
    case "source_incomplete": return "A resposta do Wazuh veio parcial e não pode ser tratada como inventário completo.";
  }
}
