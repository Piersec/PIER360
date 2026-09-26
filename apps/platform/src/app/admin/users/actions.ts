"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { AuthorizationError, requirePlatformSuperAdmin } from "@/lib/auth/authorization";
import { createAdminClient } from "@/lib/supabase/admin";

const modules = ["dashboard", "assets", "vulnerabilities"] as const;
const roles = ["tenant_admin", "analyst", "reader"] as const;
const capabilities = ["read", "manage"] as const;

function parseAccess(formData: FormData) {
  const userId = String(formData.get("user_id") ?? "");
  const tenantId = String(formData.get("tenant_id") ?? "");
  const fullName = String(formData.get("full_name") ?? "").trim();
  const role = String(formData.get("role") ?? "");
  const capability = String(formData.get("capability") ?? "read");
  const moduleKeys = formData.getAll("module_keys").map(String);

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId)) {
    throw new Error("invalid_user_id");
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(tenantId)) {
    throw new Error("invalid_tenant_id");
  }
  if (!fullName || fullName.length > 160) throw new Error("invalid_full_name");
  if (!roles.includes(role as (typeof roles)[number])) throw new Error("invalid_role");
  if (!capabilities.includes(capability as (typeof capabilities)[number])) throw new Error("invalid_capability");
  if (moduleKeys.length > modules.length || moduleKeys.some((key) => !modules.includes(key as (typeof modules)[number]))) {
    throw new Error("invalid_module_access");
  }

  return { userId, tenantId, fullName, role, capability, moduleKeys };
}

async function requireAdminContext() {
  try {
    return await requirePlatformSuperAdmin();
  } catch (error) {
    if (error instanceof AuthorizationError && error.status === 401) redirect("/login");
    redirect("/dashboard");
  }
}

function goWithNotice(notice: string): never {
  redirect(`/admin/users?notice=${encodeURIComponent(notice)}`);
}

export async function inviteTenantMember(formData: FormData) {
  const { supabase } = await requireAdminContext();
  const email = String(formData.get("email") ?? "").trim().toLowerCase();
  const fullName = String(formData.get("full_name") ?? "").trim();
  const tenantId = String(formData.get("tenant_id") ?? "");
  const role = String(formData.get("role") ?? "reader");
  const capability = String(formData.get("capability") ?? "read");
  const moduleKeys = formData.getAll("module_keys").map(String);

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) goWithNotice("invalid_email");
  if (!fullName || fullName.length > 160) goWithNotice("invalid_full_name");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(tenantId)) goWithNotice("invalid_tenant_id");
  if (!roles.includes(role as (typeof roles)[number])) goWithNotice("invalid_role");
  if (!capabilities.includes(capability as (typeof capabilities)[number])) goWithNotice("invalid_capability");
  if (moduleKeys.length > modules.length || moduleKeys.some((key) => !modules.includes(key as (typeof modules)[number]))) {
    goWithNotice("invalid_module_access");
  }
  if (!process.env.PIER360_APP_URL) goWithNotice("app_url_not_configured");

  let inviteUrl: string;
  try {
    const appUrl = new URL(process.env.PIER360_APP_URL);
    if (process.env.NODE_ENV === "production" && appUrl.protocol !== "https:") goWithNotice("app_url_not_configured");
    inviteUrl = new URL("/auth/callback?next=/reset-password", appUrl).toString();
  } catch {
    goWithNotice("app_url_not_configured");
  }

  let createdUserId: string | undefined;
  let notice: string | undefined;
  try {
    const admin = createAdminClient();
    const { data, error } = await admin.auth.admin.inviteUserByEmail(email, {
      data: { full_name: fullName },
      redirectTo: inviteUrl,
    });
    if (error || !data.user?.id) throw new Error("invite_failed");
    createdUserId = data.user.id;

    const { error: provisionError } = await supabase.rpc("pier360_provision_tenant_member", {
      target_user_id: createdUserId,
      target_tenant_id: tenantId,
      target_full_name: fullName,
      target_membership_role: role,
      target_module_keys: moduleKeys,
      target_module_capability: capability,
    });
    if (provisionError) {
      await admin.auth.admin.deleteUser(createdUserId);
      createdUserId = undefined;
      throw new Error("member_provision_failed");
    }
  } catch (error) {
    if (createdUserId) {
      try {
        await createAdminClient().auth.admin.deleteUser(createdUserId);
      } catch {
        // The invite remains unusable without its tenant membership and grants.
      }
    }
    if (error instanceof Error && error.message === "supabase_admin_not_configured") {
      notice = "admin_api_not_configured";
    } else if (error instanceof Error && error.message === "member_provision_failed") {
      notice = "member_provision_failed";
    } else {
      notice = "invite_failed";
    }
  }

  if (notice) goWithNotice(notice);

  revalidatePath("/admin/users");
  goWithNotice("invite_sent");
}

export async function updateTenantMemberAccess(formData: FormData) {
  const { supabase } = await requireAdminContext();
  let access: ReturnType<typeof parseAccess>;
  try {
    access = parseAccess(formData);
  } catch {
    goWithNotice("invalid_member_access");
  }

  const status = String(formData.get("status") ?? "");
  if (!["invited", "active", "disabled"].includes(status)) goWithNotice("invalid_status");
  if (status === "active") {
    let emailConfirmed = false;
    try {
      const { data, error } = await createAdminClient().auth.admin.getUserById(access.userId);
      emailConfirmed = !error && Boolean(data.user?.email_confirmed_at);
    } catch {
      goWithNotice("admin_api_not_configured");
    }
    if (!emailConfirmed) goWithNotice("email_not_confirmed");
  }

  const { error } = await supabase.rpc("pier360_update_tenant_member_access", {
    target_user_id: access.userId,
    target_tenant_id: access.tenantId,
    target_full_name: access.fullName,
    target_membership_role: access.role,
    target_membership_status: status,
    target_module_keys: access.moduleKeys,
    target_module_capability: access.capability,
  });
  if (error) {
    goWithNotice(error.code === "22023" ? "member_access_rejected" : "member_access_update_failed");
  }

  revalidatePath("/admin/users");
  goWithNotice("member_access_updated");
}
