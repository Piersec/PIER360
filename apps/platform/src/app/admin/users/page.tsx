import Link from "next/link";
import { redirect } from "next/navigation";
import { Brand } from "@/components/Brand";
import { AuthorizationError, requirePlatformSuperAdmin } from "@/lib/auth/authorization";
import { createAdminClient, hasSupabaseAdminConfig } from "@/lib/supabase/admin";
import type { User } from "@supabase/supabase-js";
import { grantAdditionalTenantAccess, inviteTenantMember, updateTenantMemberAccess } from "./actions";

export const dynamic = "force-dynamic";

const moduleOptions = [
  { key: "dashboard", label: "Dashboard" },
  { key: "assets", label: "Ativos" },
  { key: "vulnerabilities", label: "Vulnerabilidades" },
] as const;

const notices: Record<string, string> = {
  invite_sent: "Convite enviado. O acesso será ativado quando a pessoa confirmar o e-mail.",
  member_access_updated: "Acesso atualizado e registrado na auditoria.",
  tenant_access_granted: "Acesso aos tenants selecionados concedido sem alterar os vínculos existentes. A alteração foi registrada na auditoria.",
  app_url_not_configured: "Configure PIER360_APP_URL e adicione a URL de callback à lista permitida do Supabase Auth.",
  admin_api_not_configured: "Configure SUPABASE_SECRET_KEY somente como variável de ambiente server-side para habilitar convites e consulta de usuários.",
  invalid_email: "Informe um e-mail válido.",
  invalid_full_name: "Informe um nome entre 1 e 160 caracteres.",
  invalid_tenant_id: "Selecione um tenant ativo.",
  invalid_tenant_ids: "Selecione ao menos um tenant ativo, sem duplicações.",
  invalid_role: "O papel informado não é válido.",
  invalid_capability: "O nível de acesso informado não é válido.",
  invalid_module_access: "Revise as telas selecionadas.",
  invalid_status: "O status informado não é válido.",
  invalid_member_access: "Revise os dados de acesso antes de salvar.",
  member_access_rejected: "O acesso não foi alterado. Confirme o e-mail do usuário e revise tenant, papel e telas.",
  email_not_confirmed: "A conta ainda não confirmou o e-mail. O acesso ativo exige confirmação do convite.",
  member_access_update_failed: "Não foi possível atualizar o acesso.",
  tenant_access_rejected: "O acesso não foi concedido. Revise se todos os tenants estão ativos e se o perfil do usuário está habilitado.",
  tenant_access_grant_failed: "Não foi possível adicionar o acesso aos tenants selecionados.",
  member_provision_failed: "O convite não foi associado ao tenant. A criação foi revertida ou precisa de revisão operacional.",
  invite_failed: "Não foi possível concluir o convite. Verifique se o e-mail já possui conta e a configuração de Auth.",
};

function moduleLabel(key: string) {
  return moduleOptions.find((item) => item.key === key)?.label ?? key;
}

export default async function AdminUsersPage({
  searchParams,
}: PageProps<"/admin/users">) {
  const { supabase } = await requireAdmin();
  const { notice, page: pageQuery } = await searchParams;
  const noticeKey = Array.isArray(notice) ? notice[0] : notice;
  const requestedPage = Array.isArray(pageQuery) ? pageQuery[0] : pageQuery;
  const currentPage = Math.max(1, Math.min(10000, Number.parseInt(requestedPage ?? "1", 10) || 1));
  const { data: tenantRows, error: tenantsError } = await supabase
    .from("tenants")
    .select("id, name, status")
    .order("name");
  const activeTenantRows = (tenantRows ?? []).filter((tenant) => tenant.status === "active");
  const { data: auditRows, error: auditError } = await supabase
    .from("audit_log")
    .select("id, actor_user_id, event_type, target_table, target_key, tenant_id, created_at")
    .order("created_at", { ascending: false })
    .limit(50);

  let authUsers: Pick<User, "id" | "email">[] = [];
  let loadError = tenantsError || auditError ? "Não foi possível carregar os dados administrativos." : "";

  if (hasSupabaseAdminConfig()) {
    try {
      const { data, error } = await createAdminClient().auth.admin.listUsers({ page: currentPage, perPage: 100 });
      if (error) loadError = "Não foi possível carregar os usuários do Supabase Auth.";
      else authUsers = data.users;
    } catch {
      loadError = "O serviço de gestão de usuários não está disponível agora.";
    }
  } else {
    loadError = "SUPABASE_SECRET_KEY ainda não configurada no servidor. A tela de convites e a listagem precisam dessa chave server-side.";
  }

  const userIds = authUsers.map((user) => user.id);
  const [profilesResult, membershipsResult, permissionsResult] = userIds.length
    ? await Promise.all([
        supabase.from("profiles").select("id, full_name, status").in("id", userIds),
        supabase.from("tenant_memberships").select("tenant_id, user_id, role, status").in("user_id", userIds),
        supabase.from("user_module_permissions").select("tenant_id, user_id, module_key, capability").in("user_id", userIds),
      ])
    : [
        { data: [], error: null },
        { data: [], error: null },
        { data: [], error: null },
      ];

  if (profilesResult.error || membershipsResult.error || permissionsResult.error) {
    loadError = "Não foi possível carregar as permissões do tenant.";
  }

  const profiles = new Map((profilesResult.data ?? []).map((profile) => [profile.id, profile]));
  const tenants = new Map((tenantRows ?? []).map((tenant) => [tenant.id, tenant]));
  const grants = new Map<string, Map<string, string>>();
  for (const grant of permissionsResult.data ?? []) {
    const key = `${grant.tenant_id}:${grant.user_id}`;
    const current = grants.get(key) ?? new Map<string, string>();
    current.set(grant.module_key, grant.capability);
    grants.set(key, current);
  }

  const userRows = authUsers.map((authUser) => {
    const memberships = (membershipsResult.data ?? [])
      .filter((membership) => membership.user_id === authUser.id)
      .map((membership) => ({
        membership,
        tenant: tenants.get(membership.tenant_id),
        moduleGrants: grants.get(`${membership.tenant_id}:${membership.user_id}`) ?? new Map<string, string>(),
      }));
    const existingTenantIds = new Set(memberships.map(({ membership }) => membership.tenant_id));
    return {
      authUser,
      profile: profiles.get(authUser.id),
      memberships,
      availableTenants: activeTenantRows.filter((tenant) => !existingTenantIds.has(tenant.id)),
    };
  });

  return (
    <main className="dashboard-shell admin-shell">
      <header className="dashboard-top">
        <Brand />
        <nav className="admin-top-actions" aria-label="Navegação administrativa">
          <Link className="secondary-button" href="/dashboard">Dashboard</Link>
          <form action="/auth/signout" method="post">
            <button className="secondary-button" type="submit">Sair</button>
          </form>
        </nav>
      </header>

      <section className="admin-content">
        <p className="eyebrow">Administração global · Super Admin</p>
        <h1>Usuários e acessos</h1>
        <p className="intro">Associe cada pessoa a um ou mais tenants e controle, separadamente, quais áreas e operações ficam disponíveis em cada vínculo.</p>

        {noticeKey && notices[noticeKey] ? <p className={noticeKey === "invite_sent" || noticeKey === "member_access_updated" || noticeKey === "tenant_access_granted" ? "notice" : "alert"} role="status">{notices[noticeKey]}</p> : null}
        {loadError ? <p className="alert" role="alert">{loadError}</p> : null}

        <section className="admin-panel" aria-labelledby="invite-heading">
          <div className="admin-panel-heading">
            <div>
              <p className="eyebrow">Novo acesso</p>
              <h2 id="invite-heading">Convidar usuário</h2>
            </div>
          </div>
          <form action={inviteTenantMember} className="admin-form">
            <div className="admin-form-grid">
              <label className="field">
                <span>Nome</span>
                <input name="full_name" autoComplete="name" maxLength={160} required />
              </label>
              <label className="field">
                <span>E-mail corporativo</span>
                <input name="email" type="email" autoComplete="email" maxLength={254} required />
              </label>
              <label className="field">
                <span>Papel operacional</span>
                <select name="role" defaultValue="reader">
                  <option value="reader">Leitor</option>
                  <option value="analyst">Analista</option>
                  <option value="tenant_admin">Administrador do tenant</option>
                </select>
              </label>
            </div>

            <fieldset className="tenant-access">
              <legend>Tenants com acesso</legend>
              <p className="field-help">Selecione um ou mais tenants ativos para este novo usuário.</p>
              {activeTenantRows.length ? (
                <div className="tenant-options">
                  {activeTenantRows.map((tenant) => (
                    <label className="tenant-option" key={tenant.id}>
                      <input name="tenant_ids" type="checkbox" value={tenant.id} />
                      <span>{tenant.name}</span>
                    </label>
                  ))}
                </div>
              ) : <p className="empty-state">Não há tenants ativos para selecionar.</p>}
            </fieldset>

            <fieldset className="module-access">
              <legend>Telas habilitadas</legend>
              <div className="module-options">
                {moduleOptions.map((module) => (
                  <label className="module-option" key={module.key}>
                    <input name="module_keys" type="checkbox" value={module.key} />
                    <span>{module.label}</span>
                  </label>
                ))}
              </div>
            </fieldset>
            <label className="field access-level">
              <span>Permissão nas telas selecionadas</span>
              <select name="capability" defaultValue="read">
                <option value="read">Visualizar</option>
                <option value="manage">Visualizar e gerenciar</option>
              </select>
            </label>
            <div className="form-submit-row">
              <button className="primary-button" type="submit" disabled={!activeTenantRows.length}>Enviar convite</button>
            </div>
          </form>
        </section>

        <section className="admin-panel" aria-labelledby="members-heading">
          <div className="admin-panel-heading">
            <div>
              <p className="eyebrow">Acessos existentes</p>
              <h2 id="members-heading">Membros por tenant</h2>
            </div>
            <span className="admin-count">Página {currentPage} · {userRows.length} usuários</span>
          </div>
          {userRows.length ? (
            <div className="member-list">
              {userRows.map(({ authUser, profile, memberships, availableTenants }) => {
                const statuses = memberships.map(({ membership }) => membership.status);
                const userStatus = statuses.includes("active") ? "active" : statuses.includes("invited") ? "invited" : "disabled";
                const tenantNames = memberships.map(({ tenant }) => tenant?.name ?? "Tenant indisponível");
                const accessSummary = memberships.length
                  ? memberships.map(({ tenant, moduleGrants }) => `${tenant?.name ?? "Tenant"}: ${moduleGrants.size ? [...moduleGrants].map(([key, capability]) => `${moduleLabel(key)}${capability === "manage" ? " (gerencia)" : ""}`).join(", ") : "sem telas"}`).join(" · ")
                  : "Sem tenants associados";

                return (
                  <details className="member-card" key={authUser.id}>
                    <summary>
                      <span className="member-primary">
                        <strong>{profile?.full_name || authUser.email || authUser.id}</strong>
                        <small>{authUser.email ?? "E-mail indisponível"} · {tenantNames.length ? tenantNames.join(", ") : "Sem tenants"}</small>
                      </span>
                      <span className={`status-pill status-${userStatus}`}>{memberships.length ? (userStatus === "active" ? "Ativo" : userStatus === "disabled" ? "Desativado" : "Convite pendente") : "Sem tenants"}</span>
                      <span className="member-module-summary">{accessSummary}</span>
                    </summary>
                    <div className="member-tenant-list">
                      {memberships.map(({ membership, tenant, moduleGrants }) => (
                        <section className="member-tenant-entry" key={`${membership.tenant_id}:${membership.user_id}`}>
                          <div className="member-tenant-heading">
                            <h3>{tenant?.name ?? "Tenant indisponível"}</h3>
                            <span className={`status-pill status-${membership.status}`}>{membership.status === "active" ? "Ativo" : membership.status === "disabled" ? "Desativado" : "Convite pendente"}</span>
                          </div>
                          <form action={updateTenantMemberAccess} className="member-edit-form">
                            <input type="hidden" name="user_id" value={membership.user_id} />
                            <input type="hidden" name="tenant_id" value={membership.tenant_id} />
                            <div className="admin-form-grid">
                              <label className="field">
                                <span>Nome</span>
                                <input name="full_name" defaultValue={profile?.full_name ?? ""} maxLength={160} required />
                              </label>
                              <label className="field">
                                <span>Papel operacional</span>
                                <select name="role" defaultValue={membership.role}>
                                  <option value="reader">Leitor</option>
                                  <option value="analyst">Analista</option>
                                  <option value="tenant_admin">Administrador do tenant</option>
                                </select>
                              </label>
                              <label className="field">
                                <span>Status do acesso</span>
                                <select name="status" defaultValue={membership.status}>
                                  {membership.status === "invited" ? <option value="invited">Convite pendente</option> : null}
                                  <option value="active">Ativo</option>
                                  <option value="disabled">Desativado</option>
                                </select>
                              </label>
                            </div>
                            <fieldset className="module-access">
                              <legend>Telas habilitadas para {tenant?.name ?? "este tenant"}</legend>
                              <div className="module-options">
                                {moduleOptions.map((module) => (
                                  <label className="module-option" key={module.key}>
                                    <input name="module_keys" type="checkbox" value={module.key} defaultChecked={moduleGrants.has(module.key)} />
                                    <span>{module.label}</span>
                                  </label>
                                ))}
                              </div>
                            </fieldset>
                            <label className="field access-level">
                              <span>Permissão nas telas selecionadas</span>
                              <select name="capability" defaultValue={new Set(moduleGrants.values()).size === 1 ? [...moduleGrants.values()][0] : "read"}>
                                <option value="read">Visualizar</option>
                                <option value="manage">Visualizar e gerenciar</option>
                              </select>
                            </label>
                            <div className="form-submit-row">
                              <button className="secondary-button" type="submit">Salvar permissões</button>
                            </div>
                          </form>
                        </section>
                      ))}
                      <section className="add-tenant-access">
                        <h3>Conceder acesso a outros tenants</h3>
                        <p className="field-help">Os vínculos atuais serão preservados. Configure o novo acesso por tenant.</p>
                        {availableTenants.length ? (
                          <form action={grantAdditionalTenantAccess} className="admin-form">
                            <input type="hidden" name="user_id" value={authUser.id} />
                            <fieldset className="tenant-access">
                              <legend>Novos tenants</legend>
                              <div className="tenant-options">
                                {availableTenants.map((tenant) => (
                                  <label className="tenant-option" key={tenant.id}>
                                    <input name="tenant_ids" type="checkbox" value={tenant.id} />
                                    <span>{tenant.name}</span>
                                  </label>
                                ))}
                              </div>
                            </fieldset>
                            <div className="admin-form-grid">
                              <label className="field">
                                <span>Papel operacional nos novos tenants</span>
                                <select name="role" defaultValue="reader">
                                  <option value="reader">Leitor</option>
                                  <option value="analyst">Analista</option>
                                  <option value="tenant_admin">Administrador do tenant</option>
                                </select>
                              </label>
                              <label className="field">
                                <span>Permissão nas telas selecionadas</span>
                                <select name="capability" defaultValue="read">
                                  <option value="read">Visualizar</option>
                                  <option value="manage">Visualizar e gerenciar</option>
                                </select>
                              </label>
                            </div>
                            <fieldset className="module-access">
                              <legend>Telas nos novos tenants</legend>
                              <div className="module-options">
                                {moduleOptions.map((module) => (
                                  <label className="module-option" key={module.key}>
                                    <input name="module_keys" type="checkbox" value={module.key} />
                                    <span>{module.label}</span>
                                  </label>
                                ))}
                              </div>
                            </fieldset>
                            <div className="form-submit-row">
                              <button className="secondary-button" type="submit">Adicionar tenants selecionados</button>
                            </div>
                          </form>
                        ) : <p className="empty-state">Este usuário já possui vínculo com todos os tenants ativos.</p>}
                      </section>
                    </div>
                  </details>
                );
              })}
            </div>
          ) : (
            <p className="empty-state">Nenhum usuário do Supabase Auth encontrado nesta página.</p>
          )}
          {hasSupabaseAdminConfig() ? (
            <div className="member-pagination" aria-label="Paginação dos usuários">
              {currentPage > 1 ? <Link className="secondary-button" href={`/admin/users?page=${currentPage - 1}`}>Página anterior</Link> : <span />}
              {authUsers.length === 100 ? <Link className="secondary-button" href={`/admin/users?page=${currentPage + 1}`}>Próxima página</Link> : null}
            </div>
          ) : null}
        </section>

        <section className="admin-panel" aria-labelledby="audit-heading">
          <div className="admin-panel-heading">
            <div>
              <p className="eyebrow">Trilha de alterações</p>
              <h2 id="audit-heading">Auditoria recente</h2>
            </div>
            <span className="admin-count">Últimos 50 eventos</span>
          </div>
          {auditRows?.length ? (
            <div className="audit-list">
              {auditRows.map((event) => (
                <article className="audit-row" key={event.id}>
                  <div className="audit-event">
                    <strong>{event.event_type === "insert" ? "Criado" : event.event_type === "update" ? "Alterado" : "Removido"}</strong>
                    <span>{event.target_table.replace("public.", "")} · {event.target_key}</span>
                  </div>
                  <span className="audit-actor">Ator {event.actor_user_id?.slice(0, 8) ?? "sistema"}</span>
                  <time dateTime={event.created_at}>{new Date(event.created_at).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}</time>
                </article>
              ))}
            </div>
          ) : (
            <p className="empty-state">Nenhuma alteração registrada.</p>
          )}
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

