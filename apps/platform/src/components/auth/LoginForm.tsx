"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState, type FormEvent } from "react";
import { TurnstileWidget } from "@/components/TurnstileWidget";
import { createClient } from "@/lib/supabase/client";
import { hasSupabaseConfig } from "@/lib/supabase/env";

export function LoginForm() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [retryKey, setRetryKey] = useState(0);
  const [errorMessage, setErrorMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const configured = hasSupabaseConfig();
  const turnstileConfigured = Boolean(process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY);
  const receiveToken = useCallback((token: string | null) => setCaptchaToken(token), []);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setErrorMessage("");

    if (!configured) {
      setErrorMessage("Este ambiente ainda não foi conectado ao Supabase.");
      return;
    }
    if (!turnstileConfigured || !captchaToken) {
      setErrorMessage("Conclua a verificação de segurança para continuar.");
      return;
    }

    setLoading(true);
    try {
      const supabase = createClient();
      const { error } = await supabase.auth.signInWithPassword({
        email: email.trim(),
        password,
        options: { captchaToken },
      });

      if (error) {
        setErrorMessage("Não foi possível autenticar. Confira os dados ou contate o administrador.");
        return;
      }

      const { data: assurance, error: assuranceError } =
        await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
      if (assuranceError) {
        setErrorMessage("Não foi possível validar o segundo fator. Tente novamente.");
        return;
      }

      const { data: factors, error: factorsError } = await supabase.auth.mfa.listFactors();
      if (factorsError) {
        setErrorMessage("Não foi possível consultar o segundo fator. Tente novamente.");
        return;
      }

      const hasVerifiedTotp = factors.totp.some((factor) => factor.status === "verified");
      if (assurance.currentLevel === "aal2") {
        router.replace("/dashboard");
      } else if (hasVerifiedTotp || assurance.nextLevel === "aal2") {
        router.replace("/mfa/challenge");
      } else {
        router.replace("/mfa/setup");
      }
      router.refresh();
    } catch {
      setErrorMessage("Não foi possível concluir o acesso. Tente novamente em instantes.");
    } finally {
      setLoading(false);
      setCaptchaToken(null);
      setRetryKey((value) => value + 1);
    }
  }

  return (
    <form className="form-stack" onSubmit={handleSubmit}>
      {!configured && <div className="alert">Configure as variáveis Supabase deste ambiente antes do login.</div>}
      {errorMessage && <div className="alert" role="alert">{errorMessage}</div>}
      <div className="field">
        <label htmlFor="email">E-mail</label>
        <input id="email" type="email" autoComplete="username" inputMode="email" autoCapitalize="none" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="voce@empresa.com" />
      </div>
      <div className="field">
        <label htmlFor="password">Senha</label>
        <input id="password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Sua senha" />
      </div>
      <div className="form-row"><Link className="text-link" href="/forgot-password">Esqueci minha senha</Link></div>
      <TurnstileWidget retryKey={retryKey} onToken={receiveToken} />
      {!turnstileConfigured && <p className="turnstile-note">Turnstile ainda não configurado. O acesso permanece bloqueado.</p>}
      <button className="primary-button" type="submit" disabled={loading || !configured || !turnstileConfigured || !captchaToken}>
        {loading ? "Validando acesso…" : "Entrar com segurança"}
      </button>
    </form>
  );
}
