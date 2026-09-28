import { requireAal2 } from "@/lib/auth/require-aal2";
import { listAccessibleTenants } from "@/lib/auth/tenant-access";
import { Brand } from "@/components/Brand";
import Link from "next/link";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const { claims, supabase } = await requireAal2();
  const email = typeof claims.email === "string" ? claims.email : "Sessão autenticada";
  const userId = typeof claims.sub === "string" ? claims.sub : "";
  const { data: isSuperAdmin, error: adminCheckError } = await supabase.rpc("pier360_is_super_admin");
  if (adminCheckError) redirect("/access-denied");

  const assetTenants = await listAccessibleTenants(supabase, userId, "assets").catch(() => []);
  const vulnerabilityTenants = await listAccessibleTenants(supabase, userId, "vulnerabilities").catch(() => []);

  if (!isSuperAdmin) {
    const { data: grants, error: grantsError } = await supabase
      .from("user_module_permissions")
      .select("tenant_id")
      .eq("user_id", userId)
      .eq("module_key", "dashboard");
    if (grantsError || !grants?.length) redirect("/access-denied");

    const accessChecks = await Promise.all(grants.map(({ tenant_id }) =>
      supabase.rpc("pier360_has_tenant_module", {
        target_tenant_id: tenant_id,
        target_module_key: "dashboard",
        required_capability: "read",
      }),
    ));
    if (!accessChecks.some(({ data, error }) => !error && data)) redirect("/access-denied");
  }

  return (
    <main className="dashboard-shell">
      <header className="dashboard-top">
        <Brand />
        <div className="admin-top-actions">
          {assetTenants.length ? <Link className="text-link" href={`/assets?tenant=${assetTenants[0].id}`}>Ativos</Link> : null}
          {vulnerabilityTenants.length ? <Link className="text-link" href={`/vulnerabilities?tenant=${vulnerabilityTenants[0].id}`}>Vulnerabilidades</Link> : null}
          {isSuperAdmin ? <Link className="text-link" href="/admin/users">Administração de usuários</Link> : null}
          {isSuperAdmin ? <Link className="text-link" href="/admin/integrations/wazuh">Integrações Wazuh</Link> : null}
          <div className="account-chip">{email}</div>
        </div>
      </header>
      <section className="dashboard-content">
        <p className="eyebrow">Ambiente de desenvolvimento</p>
        <h1>Fundação segura do PIER360</h1>
        <div className="dashboard-panel">
          <h2>A sessão foi protegida com MFA</h2>
          <p>O acesso server-side está autenticado e exige segundo fator. A primeira tela de ativos já está preparada para consultar o gateway de leitura Wazuh quando a conexão DEV for provisionada.</p>
          <div className="status-line"><span className="status-dot" aria-hidden="true" /> Autenticação Supabase · nível AAL2</div>
        </div>
        <div className="dashboard-actions">
          <form action="/auth/signout" method="post">
            <button className="secondary-button" type="submit">Sair com segurança</button>
          </form>
        </div>
      </section>
    </main>
  );
}
