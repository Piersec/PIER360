import { redirect } from "next/navigation";
import { Brand } from "@/components/Brand";
import { MfaChallengeForm } from "@/components/auth/MfaChallengeForm";
import { createClient } from "@/lib/supabase/server";

export default async function MfaChallengePage() {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getClaims();
  if (error || !data?.claims) redirect("/login");
  const { data: assurance } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  if (assurance?.currentLevel === "aal2") redirect("/dashboard");
  if (assurance?.nextLevel !== "aal2") redirect("/mfa/setup");

  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="mfa-title">
        <Brand />
        <p className="eyebrow">Verificação em duas etapas</p>
        <h1 id="mfa-title">Confirme sua identidade</h1>
        <p className="intro">Digite o código atual do aplicativo autenticador para liberar sua sessão.</p>
        <MfaChallengeForm />
      </section>
    </main>
  );
}
