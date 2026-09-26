"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { createClient } from "@/lib/supabase/client";

export function ResetPasswordForm() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [message, setMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    setErrorMessage("");
    if (password !== confirmation) {
      setErrorMessage("As senhas não coincidem.");
      return;
    }
    if (password.length < 12) {
      setErrorMessage("Use uma senha com pelo menos 12 caracteres.");
      return;
    }

    setLoading(true);
    try {
      const supabase = createClient();
      const { error } = await supabase.auth.updateUser({ password });
      if (error) {
        setErrorMessage("Não foi possível atualizar a senha. Abra novamente o link recebido por e-mail.");
        return;
      }
      await supabase.auth.signOut();
      setMessage("Senha atualizada. Você já pode entrar com a nova credencial.");
      window.setTimeout(() => router.replace("/login"), 1200);
    } catch {
      setErrorMessage("Não foi possível atualizar a senha. Abra novamente o link recebido por e-mail.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="form-stack" onSubmit={handleSubmit}>
      {message && <div className="notice" role="status">{message}</div>}
      {errorMessage && <div className="alert" role="alert">{errorMessage}</div>}
      <div className="field">
        <label htmlFor="password">Nova senha</label>
        <input id="password" type="password" autoComplete="new-password" minLength={12} required value={password} onChange={(event) => setPassword(event.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="confirmation">Confirme a nova senha</label>
        <input id="confirmation" type="password" autoComplete="new-password" minLength={12} required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
      </div>
      <button className="primary-button" type="submit" disabled={loading}>{loading ? "Salvando…" : "Atualizar senha"}</button>
      <div className="form-row"><Link className="text-link" href="/login">Voltar ao login</Link></div>
    </form>
  );
}
