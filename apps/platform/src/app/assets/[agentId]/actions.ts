"use server";

import { redirect } from "next/navigation";
import { AuthorizationError, requireTenantModuleCapability } from "@/lib/auth/authorization";
import { findTenantWazuhConnection } from "@/lib/wazuh/agents";

export async function updateAssetCriticality(formData: FormData) {
  const tenantId = stringField(formData, "tenant_id");
  const agentId = stringField(formData, "agent_id");
  const isCritical = formData.get("is_critical") === "on";
  if (!isUuid(tenantId) || !/^\d{3,32}$/.test(agentId)) redirect("/access-denied");

  const returnTo = `/assets/${encodeURIComponent(agentId)}?tenant=${encodeURIComponent(tenantId)}`;
  let context;
  try {
    context = await requireTenantModuleCapability({ tenantId, module: "assets", capability: "manage" });
  } catch (error) {
    if (error instanceof AuthorizationError && error.status === 401) redirect("/login");
    redirect("/access-denied");
  }

  let connection;
  try {
    connection = await findTenantWazuhConnection(context.supabase, tenantId);
  } catch {
    redirect(`${returnTo}&notice=classification_unavailable`);
  }
  if (!connection) redirect(`${returnTo}&notice=connection_required`);

  const { data: existing, error: lookupError } = await context.supabase
    .from("asset_classifications")
    .select("id")
    .eq("tenant_id", tenantId)
    .eq("source_connection_id", connection.id)
    .eq("source_agent_id", agentId)
    .maybeSingle();
  if (lookupError) redirect(`${returnTo}&notice=classification_unavailable`);

  const mutation = existing
    ? await context.supabase
        .from("asset_classifications")
        .update({ is_critical: isCritical, updated_by: context.userId })
        .eq("id", existing.id)
    : await context.supabase
        .from("asset_classifications")
        .insert({
          tenant_id: tenantId,
          source_connection_id: connection.id,
          source_agent_id: agentId,
          is_critical: isCritical,
          created_by: context.userId,
          updated_by: context.userId,
        });

  if (mutation.error) redirect(`${returnTo}&notice=classification_save_failed`);
  redirect(`${returnTo}&notice=classification_saved`);
}

function stringField(formData: FormData, name: string) {
  const value = formData.get(name);
  return typeof value === "string" ? value : "";
}

function isUuid(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
