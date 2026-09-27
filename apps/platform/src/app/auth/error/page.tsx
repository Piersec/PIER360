import Link from "next/link";
import { Brand } from "@/components/Brand";

export default function AuthErrorPage() {
  return (
    <main className="auth-shell">
      <section className="auth-card">
        <Brand />
        <p className="eyebrow">Link inválido ou expirado</p>
        <h1>Não foi possível confirmar o acesso</h1>
        <p className="intro">Solicite ao administrador um novo convite de acesso para concluir o cadastro.</p>
        <Link className="primary-button" href="/login">Voltar ao login</Link>
      </section>
    </main>
  );
}
