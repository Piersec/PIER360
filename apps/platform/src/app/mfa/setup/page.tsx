import { redirect } from "next/navigation";
import { Brand } from "@/components/Brand";
import { MfaSetupForm } from "@/components/auth/MfaSetupForm";
import { createClient } from "@/lib/supabase/server";

export default async function MfaSetupPage() {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getClaims();
  if (error || !data?.claims) redirect("/login");
  const { data: assurance } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  if (assurance?.currentLevel === "aal2") redirect("/dashboard");

  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="mfa-setup-title">
        <Brand />
        <p className="eyebrow">Proteção da conta</p>
        <h1 id="mfa-setup-title">Ative o autenticador</h1>
        <p className="intro">O MFA é obrigatório para acessar dados e funções administrativas do PIER360.</p>
        <MfaSetupForm />
      </section>
    </main>
  );
}
