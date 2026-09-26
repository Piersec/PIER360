import { redirect } from "next/navigation";
import { Brand } from "@/components/Brand";
import { LoginForm } from "@/components/auth/LoginForm";
import { hasSupabaseConfig } from "@/lib/supabase/env";
import { createClient } from "@/lib/supabase/server";

export default async function LoginPage() {
  if (hasSupabaseConfig()) {
    const supabase = await createClient();
    const { data } = await supabase.auth.getClaims();
    if (data?.claims) {
      const { data: assurance } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
      if (assurance?.currentLevel === "aal2") redirect("/dashboard");
      redirect(assurance?.nextLevel === "aal2" ? "/mfa/challenge" : "/mfa/setup");
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="login-title">
        <Brand />
        <p className="eyebrow">Acesso seguro</p>
        <h1 id="login-title">Entrar na plataforma</h1>
        <p className="intro">Use suas credenciais corporativas para acessar o ambiente PIER360.</p>
        <LoginForm />
        <div className="auth-foot">Acesso controlado por tenant · MFA obrigatório</div>
      </section>
    </main>
  );
}
