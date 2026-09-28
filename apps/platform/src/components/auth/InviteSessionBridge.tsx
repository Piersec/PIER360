"use client";

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";
import { hasSupabaseConfig } from "@/lib/supabase/env";

export function InviteSessionBridge() {
  const router = useRouter();
  const handled = useRef(false);

  useEffect(() => {
    if (handled.current || !hasSupabaseConfig()) return;

    const fragment = new URLSearchParams(window.location.hash.slice(1));
    if (fragment.get("type") !== "invite") {
      if (window.location.pathname === "/auth/accept-invite") router.replace("/auth/error");
      return;
    }

    const accessToken = fragment.get("access_token");
    const refreshToken = fragment.get("refresh_token");
    handled.current = true;

    window.history.replaceState(
      window.history.state,
      "",
      `${window.location.pathname}${window.location.search}`,
    );

    async function acceptInvite() {
      if (!accessToken || !refreshToken) {
        router.replace("/auth/error");
        return;
      }

      const supabase = createClient();
      const { data, error } = await supabase.auth.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });
      if (error || !data.user) {
        router.replace("/auth/error");
        return;
      }

      const { data: profile, error: profileError } = await supabase
        .from("profiles")
        .select("status")
        .eq("id", data.user.id)
        .maybeSingle();

      if (profileError || profile?.status !== "invited") {
        await supabase.auth.signOut();
        router.replace("/auth/error");
        return;
      }

      router.replace("/onboarding/password");
      router.refresh();
    }

    void acceptInvite().catch(() => router.replace("/auth/error"));
  }, [router]);

  return null;
}
