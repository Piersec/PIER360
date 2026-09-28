import "server-only";

export type WazuhGatewayErrorCode =
  | "gateway_not_configured"
  | "gateway_unavailable"
  | "gateway_unauthorized"
  | "gateway_rate_limited"
  | "gateway_invalid_response"
  | "source_auth_failed"
  | "source_incomplete";

export class WazuhGatewayError extends Error {
  constructor(readonly code: WazuhGatewayErrorCode) {
    super(code);
    this.name = "WazuhGatewayError";
  }
}

function getGatewayConfig() {
  const origin = process.env.WAZUH_GATEWAY_URL;
  const token = process.env.WAZUH_GATEWAY_SERVICE_TOKEN;
  if (!origin || !token) throw new WazuhGatewayError("gateway_not_configured");

  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new WazuhGatewayError("gateway_not_configured");
  }

  const isLocalDev = process.env.NODE_ENV === "development"
    && ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  if ((url.protocol !== "https:" && !isLocalDev) || url.username || url.password || url.search || url.hash) {
    throw new WazuhGatewayError("gateway_not_configured");
  }

  return { baseUrl: url.toString().replace(/\/+$/, ""), token };
}

export async function readWazuhGateway<T>(path: string, query?: URLSearchParams): Promise<T> {
  const { baseUrl, token } = getGatewayConfig();
  const suffix = query?.size ? `?${query.toString()}` : "";
  const url = `${baseUrl}${path}${suffix}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(8_000),
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
      },
    });
  } catch {
    throw new WazuhGatewayError("gateway_unavailable");
  }

  if (response.status === 401 || response.status === 403) {
    throw new WazuhGatewayError("gateway_unauthorized");
  }
  if (response.status === 429) throw new WazuhGatewayError("gateway_rate_limited");
  if (!response.ok) {
    let sourceError = "";
    try {
      const errorPayload = await response.json() as { error?: unknown };
      if (typeof errorPayload?.error === "string") sourceError = errorPayload.error;
    } catch {
      // Keep the gateway error generic if its body is absent or malformed.
    }
    if (sourceError === "wazuh_authentication_failed") throw new WazuhGatewayError("source_auth_failed");
    if (sourceError === "wazuh_incomplete_response") throw new WazuhGatewayError("source_incomplete");
    throw new WazuhGatewayError("gateway_unavailable");
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new WazuhGatewayError("gateway_invalid_response");
  }
  if (!payload || typeof payload !== "object") {
    throw new WazuhGatewayError("gateway_invalid_response");
  }
  return payload as T;
}
