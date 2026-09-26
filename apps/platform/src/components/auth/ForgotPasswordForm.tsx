"use client";

import Link from "next/link";
import { useCallback, useState, type FormEvent } from "react";
import { TurnstileWidget } from "@/components/TurnstileWidget";
import { createClient } from "@/lib/supabase/client";

export function ForgotPasswordForm() {
  const [email, setEmail] = useState("");
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [retryKey, setRetryKey] = useState(0);
  const [message, setMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const receiveToken = useCallback((token: string | null) => setCaptchaToken(token), []);
  const turnstileConfigured = Boolean(process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    setErrorMessage("");
    if (!captchaToken || !turnstileConfigured) {
      setErrorMessage("Conclua a verificação de segurança para continuar.");
      return;
    }

    setLoading(true);
    try {
      const supabase = createClient();
      const { error } = await supabase.auth.resetPasswordForEmail(email.trim(), {
        captchaToken,
        redirectTo: `${window.location.origin}/auth/callback?next=/reset-password`,
      });
      if (error) {
        setErrorMessage("Não foi possível iniciar a recuperação. Tente novamente mais tarde.");
      } else {
        setMessage("Se o endereço estiver cadastrado, as instruções chegarão em breve.");
      }
    } catch {
      setErrorMessage("Não foi possível iniciar a recuperação. Tente novamente mais tarde.");
    } finally {
      setLoading(false);
      setCaptchaToken(null);
      setRetryKey((value) => value + 1);
    }
  }

  return (
    <form className="form-stack" onSubmit={handleSubmit}>
      {message && <div className="notice" role="status">{message}</div>}
      {errorMessage && <div className="alert" role="alert">{errorMessage}</div>}
      <div className="field">
        <label htmlFor="email">E-mail corporativo</label>
        <input id="email" type="email" autoComplete="email" inputMode="email" autoCapitalize="none" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="voce@empresa.com" />
      </div>
      <TurnstileWidget retryKey={retryKey} onToken={receiveToken} />
      {!turnstileConfigured && <p className="turnstile-note">Turnstile ainda não configurado. A recuperação permanece bloqueada.</p>}
      <button className="primary-button" type="submit" disabled={loading || !turnstileConfigured || !captchaToken}>
        {loading ? "Enviando…" : "Enviar instruções"}
      </button>
      <div className="form-row"><Link className="text-link" href="/login">Voltar ao login</Link></div>
    </form>
  );
}
