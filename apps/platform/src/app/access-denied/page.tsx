import { Brand } from "@/components/Brand";

export default function AccessDeniedPage() {
  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="denied-title">
        <Brand />
        <p className="eyebrow">Acesso restrito</p>
        <h1 id="denied-title">Seu acesso ainda não está habilitado</h1>
        <p className="intro">Peça ao Super Admin para confirmar seu vínculo com um tenant e liberar o módulo Dashboard.</p>
        <form action="/auth/signout" method="post">
          <button className="secondary-button" type="submit">Sair com segurança</button>
        </form>
      </section>
    </main>
  );
}
