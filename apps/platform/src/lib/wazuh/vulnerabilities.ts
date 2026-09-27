import "server-only";

import { AuthorizationError } from "@/lib/auth/authorization";
import { readWazuhGateway, WazuhGatewayError } from "@/lib/wazuh/gateway";
import type { createClient } from "@/lib/supabase/server";
import { findTenantWazuhConnection, type ActiveWazuhConnection } from "@/lib/wazuh/agents";

type SessionSupabase = Awaited<ReturnType<typeof createClient>>;
export type VulnerabilitySeverity = "critical" | "high" | "medium" | "low" | "unknown";

export type VulnerabilityFinding = {
  findingKey: string;
  agentId: string | null;
  agentName: string | null;
  agentIp: string | null;
  cve: string | null;
  packageName: string | null;
  packageVersion: string | null;
  severity: VulnerabilitySeverity;
  cvssScore: number | null;
  detectedAt: string | null;
};

export type VulnerabilitySummary = {
  source: "wazuh-indexer";
  completeness: "complete" | "partial";
  queriedAt: string;
  total: number;
  severity: Record<VulnerabilitySeverity, number>;
};

export type VulnerabilityPage = {
  source: "wazuh-indexer";
  completeness: "complete" | "partial";
  queriedAt: string;
  items: VulnerabilityFinding[];
  page: { limit: number; offset: number; total: number };
};

export async function findTenantIndexerConnection(supabase: SessionSupabase, tenantId: string) {
  // A connection row represents the tenant's Wazuh environment; gateway credentials
  // remain outside Supabase and are referenced only by the gateway configuration.
  return findTenantWazuhConnection(supabase, tenantId) as Promise<ActiveWazuhConnection | null>;
}

function connectionPath(connectionKey: string) {
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(connectionKey)) {
    throw new WazuhGatewayError("gateway_invalid_response");
  }
  return `/v1/connections/${encodeURIComponent(connectionKey)}/vulnerabilities`;
}

export async function readVulnerabilitySummary(connectionKey: string): Promise<VulnerabilitySummary> {
  const payload = await readWazuhGateway<VulnerabilitySummary>(`${connectionPath(connectionKey)}/summary`);
  if (payload.source !== "wazuh-indexer" || payload.completeness !== "complete"
    || !isIsoDate(payload.queriedAt) || !isCount(payload.total)
    || !payload.severity || (Object.keys(severityLabels) as VulnerabilitySeverity[])
      .some((key) => !isCount(payload.severity[key]))) {
    throw new WazuhGatewayError(payload.completeness === "partial" ? "source_incomplete" : "gateway_invalid_response");
  }
  const sum = Object.values(payload.severity).reduce((total, count) => total + count, 0);
  if (sum !== payload.total) throw new WazuhGatewayError("gateway_invalid_response");
  return payload;
}

export async function readVulnerabilityPage(
  connectionKey: string,
  input: { limit: number; offset: number; search?: string; severity?: VulnerabilitySeverity },
): Promise<VulnerabilityPage> {
  if (!Number.isInteger(input.limit) || input.limit < 1 || input.limit > 100
    || !Number.isInteger(input.offset) || input.offset < 0
    || (input.search !== undefined && input.search.length > 100)) {
    throw new WazuhGatewayError("gateway_invalid_response");
  }
  const query = new URLSearchParams({ limit: String(input.limit), offset: String(input.offset) });
  if (input.search) query.set("search", input.search);
  if (input.severity) query.set("severity", input.severity);
  const payload = await readWazuhGateway<VulnerabilityPage>(connectionPath(connectionKey), query);
  if (payload.source !== "wazuh-indexer" || payload.completeness !== "complete"
    || !isIsoDate(payload.queriedAt) || !Array.isArray(payload.items)
    || !isCount(payload.page?.limit) || !isCount(payload.page?.offset)
    || !isCount(payload.page?.total) || payload.page.limit !== input.limit || payload.page.offset !== input.offset
    || payload.items.length > input.limit || payload.items.some((item) => !isFinding(item))) {
    throw new WazuhGatewayError(payload.completeness === "partial" ? "source_incomplete" : "gateway_invalid_response");
  }
  return payload;
}

const severityLabels: Record<VulnerabilitySeverity, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Média",
  low: "Baixa",
  unknown: "Não classificada",
};

function isFinding(value: unknown): value is VulnerabilityFinding {
  if (!value || typeof value !== "object") return false;
  const finding = value as Partial<VulnerabilityFinding>;
  return typeof finding.findingKey === "string" && finding.findingKey.trim().length > 0 && finding.findingKey.length <= 512
    && !/[\u0000-\u001f\u007f]/.test(finding.findingKey)
    && nullableString(finding.agentId, 32) && nullableString(finding.agentName, 255)
    && nullableString(finding.agentIp, 64) && nullableString(finding.cve, 32)
    && nullableString(finding.packageName, 512) && nullableString(finding.packageVersion, 255)
    && Object.hasOwn(severityLabels, finding.severity as string)
    && (finding.cvssScore === null || (typeof finding.cvssScore === "number" && Number.isFinite(finding.cvssScore) && finding.cvssScore >= 0 && finding.cvssScore <= 10))
    && (finding.detectedAt === null || isIsoDate(finding.detectedAt));
}

function nullableString(value: unknown, max: number): value is string | null {
  return value === null || (typeof value === "string" && value.length <= max);
}

function isIsoDate(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}
