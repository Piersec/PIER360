import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PIER360 | Plataforma Unificada de Segurança",
  description: "Ambiente seguro de acesso à plataforma PIER360.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="pt-BR">
      <body>{children}</body>
    </html>
  );
}
