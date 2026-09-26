import { createClient } from "@/lib/supabase/server";

export type PlatformModule = "dashboard" | "assets" | "vulnerabilities";
export type ModuleCapability = "read" | "manage";

export class AuthorizationError extends Error {
  constructor(
    readonly status: 401 | 403 | 400 | 503,
    readonly code: string,
  ) {
    super(code);
    this.name = "AuthorizationError";
  }
}

async function requireAal2Identity() {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getClaims();
  const userId = data?.claims?.sub;

  if (error || typeof userId !== "string") {
    throw new AuthorizationError(401, "authentication_required");
  }

  const { data: assurance, error: assuranceError } =
    await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  if (assuranceError) {
    throw new AuthorizationError(503, "authentication_check_unavailable");
  }
  if (assurance?.currentLevel !== "aal2") {
    throw new AuthorizationError(403, "mfa_required");
  }

  return { supabase, userId };
}

export async function requirePlatformSuperAdmin() {
  const context = await requireAal2Identity();
  const { data: allowed, error } = await context.supabase.rpc("pier360_is_super_admin");
  if (error) throw new AuthorizationError(503, "authorization_check_unavailable");
  if (!allowed) throw new AuthorizationError(403, "super_admin_required");
  return context;
}

export async function requireTenantModuleCapability(input: {
  tenantId: string;
  module: PlatformModule;
  capability?: ModuleCapability;
}) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.tenantId)) {
    throw new AuthorizationError(400, "invalid_tenant_id");
  }

  const context = await requireAal2Identity();
  const { data: isSuperAdmin, error: adminError } =
    await context.supabase.rpc("pier360_is_super_admin");
  if (adminError) throw new AuthorizationError(503, "authorization_check_unavailable");
  if (isSuperAdmin) return context;

  const { data: allowed, error } = await context.supabase.rpc("pier360_has_tenant_module", {
    target_tenant_id: input.tenantId,
    target_module_key: input.module,
    required_capability: input.capability ?? "read",
  });
  if (error) throw new AuthorizationError(503, "authorization_check_unavailable");
  if (!allowed) throw new AuthorizationError(403, "tenant_module_access_denied");
  return context;
}
