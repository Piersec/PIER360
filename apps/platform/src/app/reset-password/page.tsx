import { Brand } from "@/components/Brand";
import { ResetPasswordForm } from "@/components/auth/ResetPasswordForm";

export default function ResetPasswordPage() {
  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="reset-title">
        <Brand />
        <p className="eyebrow">Atualização de credencial</p>
        <h1 id="reset-title">Crie uma nova senha</h1>
        <p className="intro">Use uma senha longa e exclusiva para proteger sua conta.</p>
        <ResetPasswordForm />
      </section>
    </main>
  );
}
