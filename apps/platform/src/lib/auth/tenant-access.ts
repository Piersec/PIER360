import { AuthorizationError, type PlatformModule } from "@/lib/auth/authorization";
import type { createClient } from "@/lib/supabase/server";

type SessionSupabase = Awaited<ReturnType<typeof createClient>>;

export type AccessibleTenant = {
  id: string;
  name: string;
  slug: string;
};

export async function listAccessibleTenants(
  supabase: SessionSupabase,
  userId: string,
  module: PlatformModule,
): Promise<AccessibleTenant[]> {
  const { data: isSuperAdmin, error: adminError } = await supabase.rpc("pier360_is_super_admin");
  if (adminError) throw new AuthorizationError(503, "authorization_check_unavailable");

  let tenantIds: string[] | null = null;
  if (!isSuperAdmin) {
    const { data: grants, error: grantsError } = await supabase
      .from("user_module_permissions")
      .select("tenant_id")
      .eq("user_id", userId)
      .eq("module_key", module)
      .in("capability", ["read", "manage"]);
    if (grantsError) throw new AuthorizationError(503, "authorization_check_unavailable");

    const candidateIds = [...new Set((grants ?? []).map(({ tenant_id }) => tenant_id))];
    const checks = await Promise.all(candidateIds.map(async (tenantId) => {
      const { data, error } = await supabase.rpc("pier360_has_tenant_module", {
        target_tenant_id: tenantId,
        target_module_key: module,
        required_capability: "read",
      });
      return !error && data ? tenantId : null;
    }));
    tenantIds = checks.filter((tenantId): tenantId is string => tenantId !== null);
  }

  if (tenantIds?.length === 0) return [];

  let query = supabase
    .from("tenants")
    .select("id, name, slug")
    .eq("status", "active")
    .order("name");
  if (tenantIds) query = query.in("id", tenantIds);

  const { data, error } = await query;
  if (error) throw new AuthorizationError(503, "tenant_list_unavailable");
  return data ?? [];
}

