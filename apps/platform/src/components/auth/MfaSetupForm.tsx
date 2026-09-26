"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { createClient } from "@/lib/supabase/client";

type TotpSetup = { id: string; qrCode: string; secret: string };

export function MfaSetupForm() {
  const router = useRouter();
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  useEffect(() => {
    let active = true;
    async function enroll() {
      try {
        const supabase = createClient();
        const { data: assurance } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
        if (assurance?.currentLevel === "aal2") {
          router.replace("/dashboard");
          return;
        }

        const { data: factors, error: listError } = await supabase.auth.mfa.listFactors();
        if (listError) throw listError;
        const verified = factors.totp.find((factor) => factor.status === "verified");
        if (verified) {
          router.replace("/mfa/challenge");
          return;
        }

        for (const pending of factors.totp.filter((factor) => factor.status !== "verified")) {
          const { error: cleanupError } = await supabase.auth.mfa.unenroll({ factorId: pending.id });
          if (cleanupError) throw cleanupError;
        }

        const { data, error } = await supabase.auth.mfa.enroll({
          factorType: "totp",
          friendlyName: "PIER360 Authenticator",
        });
        if (error) throw error;
        if (active) setSetup({ id: data.id, qrCode: data.totp.qr_code, secret: data.totp.secret });
      } catch {
        if (active) setErrorMessage("Não foi possível iniciar o cadastro do autenticador. Tente novamente ou contate o administrador.");
      } finally {
        if (active) setLoading(false);
      }
    }
    void enroll();
    return () => { active = false; };
  }, [router]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setErrorMessage("");
    if (!setup || code.replace(/\D/g, "").length !== 6) {
      setErrorMessage("Informe o código de seis dígitos do autenticador.");
      return;
    }

    setSaving(true);
    try {
      const supabase = createClient();
      const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({ factorId: setup.id });
      if (challengeError) throw challengeError;
      const { error } = await supabase.auth.mfa.verify({
        factorId: setup.id,
        challengeId: challenge.id,
        code: code.replace(/\D/g, ""),
      });
      if (error) {
        setErrorMessage("O código não foi aceito. Confira o relógio do dispositivo e tente novamente.");
        setCode("");
        return;
      }
      const { error: activationError } = await supabase.rpc("pier360_activate_current_memberships");
      if (activationError) throw activationError;
      router.replace("/dashboard");
      router.refresh();
    } catch {
      setErrorMessage("Não foi possível concluir a ativação após confirmar o autenticador. Tente novamente.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="form-stack" onSubmit={handleSubmit}>
      {errorMessage && <div className="alert" role="alert">{errorMessage}</div>}
      {loading && <div className="notice" role="status">Preparando o autenticador…</div>}
      {setup && (
        <>
          <div className="qr-frame"><img src={setup.qrCode} alt="QR code para configurar o autenticador TOTP" /></div>
          <p className="turnstile-note">Escaneie com seu aplicativo autenticador. Se necessário, digite a chave manual:</p>
          <code className="secret-code">{setup.secret}</code>
          <div className="field">
            <label htmlFor="totp-code">Código de seis dígitos</label>
            <input id="totp-code" className="otp-input" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" maxLength={7} required value={code} onChange={(event) => setCode(event.target.value.replace(/[^0-9 ]/g, ""))} placeholder="000 000" />
          </div>
          <button className="primary-button" type="submit" disabled={saving || loading || !setup}>
            {saving ? "Confirmando…" : "Ativar MFA e continuar"}
          </button>
        </>
      )}
      {!loading && !setup && !errorMessage && <div className="alert">O cadastro não pôde ser iniciado.</div>}
      <div className="form-row"><Link className="text-link" href="/login">Voltar ao login</Link></div>
    </form>
  );
}
