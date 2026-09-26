import { Brand } from "@/components/Brand";
import { ForgotPasswordForm } from "@/components/auth/ForgotPasswordForm";

export default function ForgotPasswordPage() {
  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="forgot-title">
        <Brand />
        <p className="eyebrow">Recuperação segura</p>
        <h1 id="forgot-title">Redefinir senha</h1>
        <p className="intro">Informe seu e-mail corporativo. Se houver uma conta, enviaremos as instruções de recuperação.</p>
        <ForgotPasswordForm />
      </section>
    </main>
  );
}
