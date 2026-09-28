import Link from "next/link";
import { redirect } from "next/navigation";
import { Brand } from "@/components/Brand";
import { AuthorizationError, requirePlatformSuperAdmin } from "@/lib/auth/authorization";
import { updateWazuhConnectionStatus } from "./actions";

export const dynamic = "force-dynamic";

const notices: Record<string, { text: string; kind: "success" | "error" }> = {
  connection_activated: { text: "Conexão ativada. A leitura do resumo de agentes no Manager e do resumo de vulnerabilidades no Indexer passou antes da alteração; a mudança foi registrada na auditoria.", kind: "success" },
  connection_disabled: { text: "Conexão desativada. As telas do PIER360 deixam de consultar essa origem; a mudança foi registrada na auditoria.", kind: "success" },
  gateway_not_configured: { text: "O gateway não está configurado neste deployment. Configure WAZUH_GATEWAY_URL e WAZUH_GATEWAY_SERVICE_TOKEN somente no ambiente server-side do Preview e publique um novo deployment.", kind: "error" },
  manager_failed: { text: "A validação do Manager falhou. A conexão continua no estado atual; confira o gateway e a API do Manager.", kind: "error" },
  indexer_failed: { text: "A validação do Indexer falhou. A conexão continua no estado atual; confira o gateway e a API do Indexer.", kind: "error" },
  both_sources_failed: { text: "As validações do Manager e do Indexer falharam. A conexão continua no estado atual; confira a URL, o token server-side e a rede do gateway.", kind: "error" },
  tenant_not_active: { text: "A conexão não foi ativada porque o tenant está suspenso.", kind: "error" },
  connection_key_invalid: { text: "A chave da conexão não corresponde ao formato aceito pelo gateway.", kind: "error" },
  invalid_request: { text: "A solicitação é inválida ou a confirmação não foi marcada.", kind: "error" },
  invalid_transition: { text: "Essa mudança de estado não é permitida.", kind: "error" },
  connection_load_failed: { text: "Não foi possível carregar a conexão. Atualize a página e tente novamente.", kind: "error" },
  connection_changed: { text: "O estado da conexão mudou desde que a página foi carregada. Atualize a página antes de tentar novamente.", kind: "error" },
  status_update_failed: { text: "Não foi possível atualizar o estado da conexão.", kind: "error" },
  data_load_failed: { text: "Não foi possível carregar conexões ou tenants. Nenhuma alteração foi feita.", kind: "error" },
};

const statusLabels: Record<string, string> = {
  pending: "Pendente",
  active: "Ativa",
  disabled: "Desativada",
};

export default async function WazuhIntegrationsPage({
  searchParams,
}: {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}) {
  const { supabase } = await requireAdmin();
  const { notice: noticeQuery } = await searchParams;
  const noticeKey = Array.isArray(noticeQuery) ? noticeQuery[0] : noticeQuery;
  const notice = noticeKey ? notices[noticeKey] : undefined;

  const { data: connections, error: connectionsError } = await supabase
    .from("wazuh_connections")
    .select("id, tenant_id, connection_key, display_name, status, created_at, updated_at")
    .order("created_at", { ascending: true });
  const tenantIds = [...new Set((connections ?? []).map((connection) => connection.tenant_id))];
  const { data: tenants, error: tenantsError } = tenantIds.length
    ? await supabase.from("tenants").select("id, name, slug, status").in("id", tenantIds)
    : { data: [], error: null };
  const loadError = connectionsError || tenantsError;
  const tenantById = new Map((tenants ?? []).map((tenant) => [tenant.id, tenant]));

  return (
    <main className="dashboard-shell admin-shell">
      <header className="dashboard-top">
        <Brand />
        <nav className="admin-top-actions" aria-label="Navegação administrativa">
          <Link className="secondary-button" href="/dashboard">Dashboard</Link>
          <Link className="secondary-button" href="/admin/users">Usuários</Link>
          <form action="/auth/signout" method="post">
            <button className="secondary-button" type="submit">Sair</button>
          </form>
        </nav>
      </header>

      <section className="admin-content">
        <p className="eyebrow">Administração global · Super Admin</p>
        <h1>Integrações Wazuh</h1>
        <p className="intro">Revise e controle as conexões configuradas. A ativação só ocorre depois que o PIER360 consegue consultar, pelo gateway, tanto o resumo de agentes do Manager quanto o resumo de vulnerabilidades do Indexer.</p>

        {notice ? <div className={notice.kind === "success" ? "notice" : "alert"} role={notice.kind === "success" ? "status" : "alert"}>{notice.text}</div> : null}
        {loadError ? <div className="alert" role="alert">{notices.data_load_failed.text}</div> : null}

        <section className="admin-panel" aria-labelledby="connection-heading">
          <div className="admin-panel-heading">
            <div>
              <p className="eyebrow">Conexões cadastradas</p>
              <h2 id="connection-heading">Wazuh</h2>
            </div>
            <span className="admin-count">{connections?.length ?? 0} conexões</span>
          </div>

          {connections?.length ? (
            <div className="integration-list">
              {connections.map((connection) => {
                const tenant = tenantById.get(connection.tenant_id);
                const statusClass = connection.status === "active" ? "status-active"
                  : connection.status === "disabled" ? "status-disabled" : "status-invited";
                return (
                  <article className="integration-card" key={connection.id}>
                    <div className="integration-card-heading">
                      <div className="member-primary">
                        <strong>{connection.display_name}</strong>
                        <small>{tenant ? `${tenant.name} · ${tenant.slug}` : "Tenant indisponível"}</small>
                      </div>
                      <span className={`status-pill ${statusClass}`}>{statusLabels[connection.status] ?? "Desconhecida"}</span>
                    </div>
                    <dl className="integration-details">
                      <div><dt>Chave</dt><dd>{connection.connection_key}</dd></div>
                      <div><dt>Tenant</dt><dd>{tenant?.status === "active" ? "Ativo" : tenant ? "Suspenso" : "Indisponível"}</dd></div>
                      <div><dt>Atualizada</dt><dd><time dateTime={connection.updated_at}>{new Date(connection.updated_at).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}</time></dd></div>
                    </dl>

                    {!loadError && connection.status !== "active" && tenant?.status === "active" ? (
                      <form action={updateWazuhConnectionStatus} className="integration-status-form">
                        <input type="hidden" name="connection_id" value={connection.id} />
                        <input type="hidden" name="expected_status" value={connection.status} />
                        <input type="hidden" name="next_status" value="active" />
                        <label className="integration-confirm">
                          <input type="checkbox" name="confirm" value="yes" required />
                          <span>Confirmo que URL e token estão configurados apenas no servidor do Preview, que o HTTPS do gateway está validado e que esta é a conexão DEV correta.</span>
                        </label>
                        <button className="primary-button" type="submit">Validar e ativar</button>
                      </form>
                    ) : null}
                    {!loadError && connection.status === "active" ? (
                      <form action={updateWazuhConnectionStatus} className="integration-status-form">
                        <input type="hidden" name="connection_id" value={connection.id} />
                        <input type="hidden" name="expected_status" value="active" />
                        <input type="hidden" name="next_status" value="disabled" />
                        <label className="integration-confirm">
                          <input type="checkbox" name="confirm" value="yes" required />
                          <span>Confirmo que quero interromper as consultas desta conexão no PIER360.</span>
                        </label>
                        <button className="secondary-button" type="submit">Desativar conexão</button>
                      </form>
                    ) : null}
                    {!loadError && connection.status !== "active" && tenant?.status !== "active" ? (
                      <p className="field-help">Ative o tenant antes de habilitar esta conexão Wazuh.</p>
                    ) : null}
                  </article>
                );
              })}
            </div>
          ) : (
            <p className="empty-state">Nenhuma conexão Wazuh cadastrada.</p>
          )}
        </section>

        <section className="admin-panel" aria-labelledby="activation-heading">
          <div className="admin-panel-heading">
            <div>
              <p className="eyebrow">Etapas do Preview</p>
              <h2 id="activation-heading">Critérios de ativação</h2>
            </div>
          </div>
          <ol className="integration-checklist">
            <li>Cloudflare ou outro caminho HTTPS de teste alcança <code>http://wazuh-gateway:8787</code> somente pelo tunnel/rede configurada.</li>
            <li>No deployment Preview, configure <code>WAZUH_GATEWAY_URL</code> e <code>WAZUH_GATEWAY_SERVICE_TOKEN</code> como variáveis server-side; nunca use prefixo <code>NEXT_PUBLIC_</code>.</li>
            <li>A ação de ativação consulta os dois resumos com o token guardado no servidor e só muda o status se ambas as respostas forem completas.</li>
          </ol>
          <p className="field-help">A interface não mostra credenciais, não salva senhas Wazuh no banco e não altera os ambientes Production.</p>
        </section>
      </section>
    </main>
  );
}

async function requireAdmin() {
  try {
    return await requirePlatformSuperAdmin();
  } catch (error) {
    if (error instanceof AuthorizationError && error.status === 401) redirect("/login");
    redirect("/dashboard");
  }
}

