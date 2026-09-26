"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { createClient } from "@/lib/supabase/client";

export function MfaChallengeForm() {
  const router = useRouter();
  const [factorId, setFactorId] = useState("");
  const [code, setCode] = useState("");
  const [loadingFactors, setLoadingFactors] = useState(true);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  useEffect(() => {
    let active = true;
    async function loadFactor() {
      try {
        const supabase = createClient();
        const { data, error } = await supabase.auth.mfa.listFactors();
        if (error) throw error;
        const verified = data.totp.find((factor) => factor.status === "verified");
        if (!active) return;
        if (verified) setFactorId(verified.id);
        else router.replace("/mfa/setup");
      } catch {
        if (active) setErrorMessage("Não foi possível localizar o autenticador desta conta.");
      } finally {
        if (active) setLoadingFactors(false);
      }
    }
    void loadFactor();
    return () => { active = false; };
  }, [router]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setErrorMessage("");
    if (!factorId || code.replace(/\D/g, "").length !== 6) {
      setErrorMessage("Informe o código de seis dígitos do autenticador.");
      return;
    }

    setLoading(true);
    try {
      const supabase = createClient();
      const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({ factorId });
      if (challengeError) throw challengeError;
      const { error } = await supabase.auth.mfa.verify({
        factorId,
        challengeId: challenge.id,
        code: code.replace(/\D/g, ""),
      });
      if (error) {
        setErrorMessage("O código não foi aceito. Confira o relógio do dispositivo e tente novamente.");
        setCode("");
        return;
      }
      router.replace("/dashboard");
      router.refresh();
    } catch {
      setErrorMessage("Não foi possível validar o código. Tente novamente.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="form-stack" onSubmit={handleSubmit}>
      {errorMessage && <div className="alert" role="alert">{errorMessage}</div>}
      <div className="field">
        <label htmlFor="totp-code">Código do autenticador</label>
        <input id="totp-code" className="otp-input" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" maxLength={7} required value={code} onChange={(event) => setCode(event.target.value.replace(/[^0-9 ]/g, ""))} placeholder="000 000" />
      </div>
      <button className="primary-button" type="submit" disabled={loading || loadingFactors || !factorId}>
        {loading ? "Verificando…" : loadingFactors ? "Carregando autenticador…" : "Confirmar segundo fator"}
      </button>
      <div className="form-row"><Link className="text-link" href="/login">Voltar ao login</Link></div>
    </form>
  );
}
