import { Brand } from "@/components/Brand";

export default function AcceptInvitePage() {
  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="invite-title">
        <Brand />
        <p className="eyebrow">Convite PIER360</p>
        <h1 id="invite-title">Validando seu convite</h1>
        <p className="intro">Aguarde enquanto confirmamos o acesso e preparamos o cadastro da sua senha.</p>
      </section>
    </main>
  );
}
