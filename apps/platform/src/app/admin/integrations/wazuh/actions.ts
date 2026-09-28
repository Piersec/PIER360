"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { AuthorizationError, requirePlatformSuperAdmin } from "@/lib/auth/authorization";
import { readAgentSummary } from "@/lib/wazuh/agents";
import { readVulnerabilitySummary } from "@/lib/wazuh/vulnerabilities";
import { WazuhGatewayError } from "@/lib/wazuh/gateway";

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const connectionStatuses = ["pending", "active", "disabled"] as const;

async function requireAdminContext() {
  try {
    return await requirePlatformSuperAdmin();
  } catch (error) {
    if (error instanceof AuthorizationError && error.status === 401) redirect("/login");
    redirect("/dashboard");
  }
}

function goWithNotice(notice: string): never {
  redirect(`/admin/integrations/wazuh?notice=${encodeURIComponent(notice)}`);
}

function isConfirmed(formData: FormData) {
  return formData.get("confirm") === "yes";
}

export async function updateWazuhConnectionStatus(formData: FormData) {
  const { supabase } = await requireAdminContext();
  const id = String(formData.get("connection_id") ?? "");
  const expectedStatus = String(formData.get("expected_status") ?? "");
  const nextStatus = String(formData.get("next_status") ?? "");

  if (!uuidPattern.test(id) || !connectionStatuses.includes(expectedStatus as (typeof connectionStatuses)[number])
    || !connectionStatuses.includes(nextStatus as (typeof connectionStatuses)[number])
    || !isConfirmed(formData)) {
    goWithNotice("invalid_request");
  }
  const allowedTransition = (nextStatus === "active" && ["pending", "disabled"].includes(expectedStatus))
    || (nextStatus === "disabled" && ["pending", "active"].includes(expectedStatus));
  if (!allowedTransition) {
    goWithNotice("invalid_transition");
  }

  const { data: connection, error: connectionError } = await supabase
    .from("wazuh_connections")
    .select("id, tenant_id, connection_key, status")
    .eq("id", id)
    .maybeSingle();
  if (connectionError || !connection) goWithNotice("connection_load_failed");
  if (connection.status !== expectedStatus) goWithNotice("connection_changed");

  if (nextStatus === "active") {
    const { data: tenant, error: tenantError } = await supabase
      .from("tenants")
      .select("status")
      .eq("id", connection.tenant_id)
      .maybeSingle();
    if (tenantError || !tenant) goWithNotice("connection_load_failed");
    if (tenant.status !== "active") goWithNotice("tenant_not_active");
    if (!/^[A-Za-z0-9._-]{1,80}$/.test(connection.connection_key)) goWithNotice("connection_key_invalid");

    const checks = await Promise.allSettled([
      readAgentSummary(connection.connection_key),
      readVulnerabilitySummary(connection.connection_key),
    ]);
    const managerOk = checks[0].status === "fulfilled";
    const indexerOk = checks[1].status === "fulfilled";
    if (!managerOk || !indexerOk) {
      if (checks.some((check) => check.status === "rejected"
        && check.reason instanceof WazuhGatewayError
        && check.reason.code === "gateway_not_configured")) {
        goWithNotice("gateway_not_configured");
      }
      if (!managerOk && !indexerOk) goWithNotice("both_sources_failed");
      if (!managerOk) goWithNotice("manager_failed");
      goWithNotice("indexer_failed");
    }
  }

  const { data: updated, error: updateError } = await supabase
    .from("wazuh_connections")
    .update({ status: nextStatus })
    .eq("id", id)
    .eq("status", expectedStatus)
    .select("id, status")
    .maybeSingle();
  if (updateError) goWithNotice("status_update_failed");
  if (!updated) goWithNotice("connection_changed");

  revalidatePath("/admin/integrations/wazuh");
  revalidatePath("/dashboard");
  revalidatePath("/assets");
  revalidatePath("/vulnerabilities");
  goWithNotice(nextStatus === "active" ? "connection_activated" : "connection_disabled");
}

