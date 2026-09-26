import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";

export async function requireAal2() {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getClaims();
  if (error || !data?.claims) redirect("/login");

  const { data: assurance, error: assuranceError } =
    await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  if (assuranceError) redirect("/login");
  if (assurance?.currentLevel !== "aal2") {
    redirect(assurance?.nextLevel === "aal2" ? "/mfa/challenge" : "/mfa/setup");
  }

  return { claims: data.claims, supabase };
}
