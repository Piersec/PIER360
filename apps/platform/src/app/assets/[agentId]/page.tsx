import Link from "next/link";
import { redirect } from "next/navigation";
import { Brand } from "@/components/Brand";
import { requireAal2 } from "@/lib/auth/require-aal2";
import { listAccessibleTenants } from "@/lib/auth/tenant-access";
import { AuthorizationError, requireTenantModuleCapability } from "@/lib/auth/authorization";
import { findTenantWazuhConnection, readAgentDetail, type AgentDetailResponse } from "@/lib/wazuh/agents";
import { WazuhGatewayError } from "@/lib/wazuh/gateway";
import { updateAssetCriticality } from "./actions";

export const dynamic = "force-dynamic";

type DetailSearch = { tenant?: string | string[]; notice?: string | string[] };

export default async function AgentDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ agentId: string }>;
  searchParams: Promise<DetailSearch>;
}) {
  const { claims, supabase } = await requireAal2();
  const userId = typeof claims.sub === "string" ? claims.sub : "";
  const [{ agentId }, search] = await Promise.all([params, searchParams]);
  const tenantId = Array.isArray(search.tenant) ? search.tenant[0] : search.tenant;
  const notice = Array.isArray(search.notice) ? search.notice[0] : search.notice;
  if (!tenantId || !/^\d{3,32}$/.test(agentId)) redirect("/access-denied");

  const tenants = await listAccessibleTenants(supabase, userId, "assets").catch(() => redirect("/access-denied"));
  const tenant = tenants.find((item) => item.id === tenantId);
  if (!tenant) redirect("/access-denied");
  await requireTenantModuleCapability({ tenantId, module: "assets", capability: "read" }).catch(() => redirect("/access-denied"));

  let detail: AgentDetailResponse | null = null;
  let connectionId: string | null = null;
  let isCritical: boolean | null = null;
  let classificationAvailable = false;
  let errorMessage = "";
  try {
    const connection = await findTenantWazuhConnection(supabase, tenantId);
    if (!connection) {
      errorMessage = `O tenant ${tenant.name} ainda não tem conexão Manager ativa cadastrada.`;
    } else {
      connectionId = connection.id;
      const { data: classification, error: classificationError } = await supabase
        .from("asset_classifications")
        .select("is_critical")
        .eq("tenant_id", tenantId)
        .eq("source_connection_id", connection.id)
        .eq("source_agent_id", agentId)
        .maybeSingle();
      if (!classificationError) {
        isCritical = classification?.is_critical ?? false;
        classificationAvailable = true;
      }
      detail = await readAgentDetail(connection.connection_key, agentId);
    }
  } catch (error) {
    if (error instanceof AuthorizationError && error.code === "wazuh_connection_lookup_unavailable") {
      errorMessage = "Não foi possível consultar a configuração autorizada do tenant.";
    } else if (error instanceof AuthorizationError && error.code === "multiple_wazuh_connections_active") {
      errorMessage = "Há mais de uma conexão Manager ativa para este tenant; a seleção precisa ser configurada antes da leitura.";
    } else {
      errorMessage = error instanceof WazuhGatewayError && error.code === "gateway_not_configured"
        ? "O gateway Wazuh ainda não está configurado no ambiente DEV."
        : "Não foi possível obter dados atuais do agente. O estado da origem permanece desconhecido.";
    }
  }

  const agent = detail?.agent;
  return (
    <main className="dashboard-shell assets-shell">
      <header className="dashboard-top">
        <Brand />
        <nav className="assets-nav" aria-label="Navegação principal">
          <Link href="/dashboard">Visão geral</Link>
          <Link className="active" aria-current="page" href={`/assets?tenant=${tenantId}`}>Ativos</Link>
          <span aria-disabled="true">Vulnerabilidades</span>
        </nav>
        <div className="account-chip">{typeof claims.email === "string" ? claims.email : "Sessão autenticada"}</div>
      </header>
      <section className="assets-content">
        <Link className="text-link" href={`/assets?tenant=${tenantId}`}>← Voltar aos ativos</Link>
        <p className="eyebrow agent-detail-eyebrow">Ficha do agente · {tenant.name}</p>
        {notice === "classification_saved" ? <p className="notice" role="status">Criticidade do ativo salva e registrada na auditoria.</p> : null}
        {notice === "classification_save_failed" || notice === "classification_unavailable" ? <p className="alert" role="alert">Não foi possível salvar a classificação crítica do ativo.</p> : null}
        {notice === "connection_required" ? <p className="alert" role="alert">É necessário haver uma conexão Wazuh ativa antes de classificar este ativo.</p> : null}
        {agent ? (
          <>
            <div className="assets-heading agent-detail-heading">
              <div><h1>{agent.name}</h1><p className="intro">Agent ID {agent.id} · {agent.osName ?? "Sistema operacional não informado"}{agent.osVersion ? ` ${agent.osVersion}` : ""}</p></div>
              <span className={`agent-status ${agent.rawStatus === "active" ? "active" : agent.rawStatus === "disconnected" ? "disconnected" : "pending"}`}>{agent.rawStatus}</span>
            </div>
            <div className="agent-detail-grid">
              <DetailItem label="IP" value={agent.ip ?? "Não informado"} />
              <DetailItem label="Status de origem" value={agent.rawStatus} />
              <DetailItem label="Último contato (lastKeepAlive)" value={formatDate(agent.lastKeepAlive)} />
              <DetailItem label="Último scan do inventário Syscollector" value={formatDate(agent.syscollectorScanAt ?? null)} />
              <DetailItem label="Consulta da Manager API" value={formatDate(detail?.queriedAt ?? null)} />
            </div>
            {agent && connectionId && !classificationAvailable ? (
              <div className="integration-error" role="alert"><strong>Classificação do ativo indisponível</strong><p>O PIER360 não conseguiu consultar o estado de criticidade salvo. Nenhum valor padrão foi aplicado.</p></div>
            ) : null}
            {classificationAvailable && connectionId && isCritical !== null ? (
              <form action={updateAssetCriticality} className="criticality-panel">
                <input type="hidden" name="tenant_id" value={tenantId} />
                <input type="hidden" name="agent_id" value={agent.id} />
                <label className="criticality-toggle">
                  <input name="is_critical" type="checkbox" defaultChecked={isCritical} />
                  <span><strong>Ativo crítico</strong><small>Classificação binária do PIER360, sem pontuação. Esta marcação serve como contexto nas métricas de vulnerabilidade.</small></span>
                </label>
                <button className="secondary-button" type="submit">Salvar classificação</button>
              </form>
            ) : null}
            <p className="field-help agent-detail-note">O scan Syscollector representa o inventário de software. Ele não é o horário de detecção de vulnerabilidades nem o último contato do agente.</p>
          </>
        ) : (
          <div className="integration-error" role="status"><strong>Ficha indisponível</strong><p>{errorMessage}</p></div>
        )}
      </section>
    </main>
  );
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return <article className="agent-detail-item"><span>{label}</span><strong>{value}</strong></article>;
}

function formatDate(value: string | null) {
  if (!value) return "Sem registro";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Data inválida";
  return new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short", timeZone: "America/Sao_Paulo" }).format(date);
}

