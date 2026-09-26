import { redirect } from "next/navigation";
import { Brand } from "@/components/Brand";
import { ResetPasswordForm } from "@/components/auth/ResetPasswordForm";
import { createClient } from "@/lib/supabase/server";

export default async function OnboardingPasswordPage() {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getClaims();
  const userId = data?.claims?.sub;
  if (error || !userId) redirect("/auth/error");

  const { data: profile, error: profileError } = await supabase
    .from("profiles")
    .select("status")
    .eq("id", userId)
    .maybeSingle();
  if (profileError || profile?.status !== "invited") redirect("/auth/error");

  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="onboarding-password-title">
        <Brand />
        <p className="eyebrow">Primeiro acesso</p>
        <h1 id="onboarding-password-title">Defina sua senha</h1>
        <p className="intro">Depois, configure o autenticador obrigatório para ativar seu acesso ao PIER360.</p>
        <ResetPasswordForm flow="invite" />
      </section>
    </main>
  );
}
