import { NextResponse, type NextRequest } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const requestedPath = request.nextUrl.searchParams.get("next") ?? "/dashboard";
  const safePath = requestedPath === "/reset-password" ? "/reset-password" : "/dashboard";

  if (!code) {
    const hasAuthError = request.nextUrl.searchParams.has("error") || request.nextUrl.searchParams.has("error_code");
    if (!hasAuthError && requestedPath === "/dashboard") {
      return NextResponse.redirect(new URL("/auth/accept-invite", request.url));
    }
    return NextResponse.redirect(new URL("/auth/error", request.url));
  }

  const supabase = await createClient();
  const { error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) {
    return NextResponse.redirect(new URL("/auth/error", request.url));
  }

  return NextResponse.redirect(new URL(safePath, request.url));
}
