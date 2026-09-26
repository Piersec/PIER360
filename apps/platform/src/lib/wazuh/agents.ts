import "server-only";

import { AuthorizationError } from "@/lib/auth/authorization";
import { readWazuhGateway, WazuhGatewayError } from "@/lib/wazuh/gateway";
import type { createClient } from "@/lib/supabase/server";

type SessionSupabase = Awaited<ReturnType<typeof createClient>>;

export type AgentStatusCounts = {
  active: number;
  disconnected: number;
  pending: number;
  neverConnected: number;
  other: number;
  total: number;
};

export type WazuhAgent = {
  id: string;
  name: string;
  ip: string | null;
  rawStatus: string;
  lastKeepAlive: string | null;
  osName: string | null;
  osVersion: string | null;
  syscollectorScanAt?: string | null;
};

export type AgentSummaryResponse = {
  source: "wazuh-manager";
  completeness: "complete" | "partial";
  queriedAt: string;
  status: AgentStatusCounts;
};

export type AgentListResponse = {
  source: "wazuh-manager";
  completeness: "complete" | "partial";
  queriedAt: string;
  items: WazuhAgent[];
  page: { limit: number; offset: number; total: number };
};

export type AgentDetailResponse = {
  source: "wazuh-manager";
  completeness: "complete" | "partial";
  queriedAt: string;
  agent: WazuhAgent;
};

export type ActiveWazuhConnection = {
  id: string;
  display_name: string;
  connection_key: string;
};

export async function findTenantWazuhConnection(
  supabase: SessionSupabase,
  tenantId: string,
): Promise<ActiveWazuhConnection | null> {
  const { data, error } = await supabase
    .from("wazuh_connections")
    .select("id, display_name, connection_key")
    .eq("tenant_id", tenantId)
    .eq("status", "active")
    .limit(2);

  if (error) throw new AuthorizationError(503, "wazuh_connection_lookup_unavailable");
  if (!data?.length) return null;
  if (data.length > 1) throw new AuthorizationError(503, "multiple_wazuh_connections_active");

  const connection = data[0];
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(connection.connection_key)) {
    throw new WazuhGatewayError("gateway_invalid_response");
  }
  return connection;
}

function connectionPath(connectionKey: string) {
  return `/v1/connections/${encodeURIComponent(connectionKey)}`;
}

export async function readAgentSummary(connectionKey: string): Promise<AgentSummaryResponse> {
  const payload = await readWazuhGateway<AgentSummaryResponse>(
    `${connectionPath(connectionKey)}/agents/summary`,
  );
  if (payload.source !== "wazuh-manager" || payload.completeness !== "complete"
    || !isIsoDate(payload.queriedAt) || !isCount(payload.status?.active)
    || !isCount(payload.status?.disconnected) || !isCount(payload.status?.pending)
    || !isCount(payload.status?.neverConnected) || !isCount(payload.status?.other)
    || !isCount(payload.status?.total)) {
    throw new WazuhGatewayError(payload.completeness === "partial" ? "source_incomplete" : "gateway_invalid_response");
  }
  const computedTotal = payload.status.active + payload.status.disconnected + payload.status.pending
    + payload.status.neverConnected + payload.status.other;
  if (computedTotal !== payload.status.total) throw new WazuhGatewayError("gateway_invalid_response");
  return payload;
}

export async function readAgentPage(
  connectionKey: string,
  input: { limit: number; offset: number; search?: string },
): Promise<AgentListResponse> {
  const query = new URLSearchParams({ limit: String(input.limit), offset: String(input.offset) });
  if (input.search) query.set("search", input.search);

  const payload = await readWazuhGateway<AgentListResponse>(
    `${connectionPath(connectionKey)}/agents`,
    query,
  );
  if (payload.source !== "wazuh-manager" || payload.completeness !== "complete"
    || !isIsoDate(payload.queriedAt) || !Array.isArray(payload.items)
    || !isCount(payload.page?.limit) || !isCount(payload.page?.offset)
    || !isCount(payload.page?.total) || payload.items.some((agent) => !isAgent(agent))) {
    throw new WazuhGatewayError(payload.completeness === "partial" ? "source_incomplete" : "gateway_invalid_response");
  }
  return payload;
}

export async function readAgentDetail(connectionKey: string, agentId: string): Promise<AgentDetailResponse> {
  if (!/^\d{3,32}$/.test(agentId)) throw new WazuhGatewayError("gateway_invalid_response");
  const payload = await readWazuhGateway<AgentDetailResponse>(
    `${connectionPath(connectionKey)}/agents/${encodeURIComponent(agentId)}`,
  );
  if (payload.source !== "wazuh-manager" || payload.completeness !== "complete"
    || !isIsoDate(payload.queriedAt) || !isAgent(payload.agent, true)) {
    throw new WazuhGatewayError(payload.completeness === "partial" ? "source_incomplete" : "gateway_invalid_response");
  }
  return payload;
}

function isAgent(value: unknown, requireScanTime = false): value is WazuhAgent {
  if (!value || typeof value !== "object") return false;
  const agent = value as Partial<WazuhAgent>;
  return typeof agent.id === "string" && agent.id.length <= 32
    && typeof agent.name === "string" && agent.name.length <= 255
    && (agent.ip === null || typeof agent.ip === "string")
    && typeof agent.rawStatus === "string" && agent.rawStatus.length <= 64
    && (agent.lastKeepAlive === null || isIsoDate(agent.lastKeepAlive))
    && (agent.osName === null || typeof agent.osName === "string")
    && (agent.osVersion === null || typeof agent.osVersion === "string")
    && (requireScanTime
      ? agent.syscollectorScanAt === null || isIsoDate(agent.syscollectorScanAt)
      : agent.syscollectorScanAt === undefined || agent.syscollectorScanAt === null || isIsoDate(agent.syscollectorScanAt));
}

function isIsoDate(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

