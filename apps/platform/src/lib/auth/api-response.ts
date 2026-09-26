import { NextResponse } from "next/server";
import { AuthorizationError } from "@/lib/auth/authorization";

export function authorizationErrorResponse(error: unknown) {
  if (error instanceof AuthorizationError) {
    return NextResponse.json(
      { error: error.code },
      { status: error.status, headers: { "Cache-Control": "private, no-store" } },
    );
  }

  return NextResponse.json(
    { error: "internal_error" },
    { status: 500, headers: { "Cache-Control": "private, no-store" } },
  );
}
