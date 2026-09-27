import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { timingSafeEqual, createHash } from "node:crypto";
import https from "node:https";

const PORT = Number(process.env.PORT ?? "8787");
// Keep the worst cold detail path (login + agent + Syscollector) inside the BFF's 8 s budget.
const REQUEST_TIMEOUT_MS = 2_200;
const MAX_BODY_BYTES = 1_000_000;
const MAX_LIMIT = 100;
const SELECT_FIELDS = "id,name,ip,status,lastKeepAlive,dateAdd,os.name,os.version";

function readSecret(name) {
  const filePath = process.env[`${name}_FILE`];
  const value = filePath ? readFileSync(filePath, "utf8").trim() : process.env[name]?.trim();
  if (!value) throw new Error(`Missing required configuration: ${name}`);
  return value;
}

function loadConfig() {
  const serviceToken = readSecret("WAZUH_GATEWAY_SERVICE_TOKEN");
  const managerUsername = readSecret("WAZUH_MANAGER_USERNAME");
  const managerPassword = readSecret("WAZUH_MANAGER_PASSWORD");
  if (managerUsername.includes(":")) throw new Error("Invalid Wazuh manager username configuration");

  let managerUrl;
  try {
    managerUrl = new URL(process.env.WAZUH_MANAGER_URL ?? "");
  } catch {
    throw new Error("Invalid Wazuh manager URL configuration");
  }
  if (managerUrl.protocol !== "https:" || managerUrl.username || managerUrl.password || managerUrl.search || managerUrl.hash) {
    throw new Error("Wazuh manager URL must be HTTPS and contain no credentials or query");
  }
  managerUrl.pathname = managerUrl.pathname.replace(/\/+$/, "");

  const connectionKey = process.env.WAZUH_CONNECTION_KEY ?? "piersec-dev";
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(connectionKey)) throw new Error("Invalid connection key configuration");

  const caFile = process.env.WAZUH_MANAGER_CA_FILE;
  const ca = caFile ? readFileSync(caFile) : undefined;
  if (ca && !ca.toString("utf8").includes("-----BEGIN CERTIFICATE-----")) {
    throw new Error("Wazuh manager CA file is not a PEM certificate");
  }

  return { serviceToken, managerUsername, managerPassword, managerUrl, connectionKey, ca };
}

const config = loadConfig();
let cachedManagerToken = "";
let managerTokenExpiresAt = 0;
let managerAuthPromise;
const rateBuckets = new Map();

function jsonResponse(response, status, value) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store, max-age=0",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  response.end(JSON.stringify(value));
}

function hashToken(value) {
  return createHash("sha256").update(value).digest();
}

function equalSecret(left, right) {
  return timingSafeEqual(hashToken(left), hashToken(right));
}

function serviceAuthorized(request) {
  const authorization = request.headers.authorization ?? "";
  const match = /^Bearer ([^\s]+)$/.exec(authorization);
  return Boolean(match && equalSecret(match[1], config.serviceToken));
}

function requestJson(url, { method = "GET", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      method,
      headers,
      ca: config.ca,
      rejectUnauthorized: true,
      timeout: REQUEST_TIMEOUT_MS,
      maxHeaderSize: 8_192,
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          request.destroy(new Error("upstream_response_too_large"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        const status = response.statusCode ?? 502;
        const body = Buffer.concat(chunks).toString("utf8");
        if (status < 200 || status >= 300) {
          reject(new UpstreamError(status === 401 || status === 403 ? "upstream_auth_failed" : "upstream_http_error"));
          return;
        }
        resolve({ status, body, contentType: response.headers["content-type"] ?? "" });
      });
    });
    request.on("timeout", () => request.destroy(new Error("upstream_timeout")));
    request.on("error", (error) => {
      if (error instanceof UpstreamError) reject(error);
      else if (error.message === "upstream_timeout") reject(new UpstreamError("upstream_timeout"));
      else if (error.message === "upstream_response_too_large") reject(new UpstreamError("upstream_response_too_large"));
      else reject(new UpstreamError("upstream_unavailable"));
    });
    request.end();
  });
}

class UpstreamError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function managerEndpoint(path, query) {
  const url = new URL(path.replace(/^\/+/, ""), `${config.managerUrl.toString().replace(/\/+$/, "")}/`);
  if (query) url.search = query.toString();
  return url;
}

async function managerLogin() {
  const now = Date.now();
  if (cachedManagerToken && now < managerTokenExpiresAt) return cachedManagerToken;
  if (managerAuthPromise) return managerAuthPromise;
  managerAuthPromise = (async () => {
    const basic = Buffer.from(`${config.managerUsername}:${config.managerPassword}`).toString("base64");
    const { body } = await requestJson(managerEndpoint("/security/user/authenticate", new URLSearchParams({ raw: "true" })), {
      method: "POST",
      headers: { authorization: `Basic ${basic}`, accept: "text/plain" },
    });
    const token = body.trim();
    if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
      throw new UpstreamError("upstream_auth_failed");
    }
    cachedManagerToken = token;
    // Wazuh's default JWT lifetime is 15 minutes; refresh early and avoid mutating Manager auth settings.
    managerTokenExpiresAt = Date.now() + 12 * 60_000;
    return token;
  })();
  try {
    return await managerAuthPromise;
  } finally {
    managerAuthPromise = undefined;
  }
}

async function managerGet(path, query, retry = true) {
  const token = await managerLogin();
  try {
    const { body, contentType } = await requestJson(managerEndpoint(path, query), {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
    if (!contentType.toLowerCase().includes("application/json")) throw new UpstreamError("upstream_invalid_response");
    let payload;
    try { payload = JSON.parse(body); } catch { throw new UpstreamError("upstream_invalid_response"); }
    if (!payload || typeof payload !== "object" || payload.error !== 0 || !payload.data) {
      throw new UpstreamError("upstream_invalid_response");
    }
    return payload;
  } catch (error) {
    if (retry && error instanceof UpstreamError && error.code === "upstream_auth_failed") {
      cachedManagerToken = "";
      managerTokenExpiresAt = 0;
      return managerGet(path, query, false);
    }
    throw error;
  }
}

function asCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function parseAgent(agent) {
  if (!agent || typeof agent !== "object" || typeof agent.id !== "string"
    || typeof agent.name !== "string" || typeof agent.status !== "string") {
    throw new UpstreamError("upstream_invalid_response");
  }
  return {
    id: agent.id,
    name: agent.name,
    ip: typeof agent.ip === "string" ? agent.ip : null,
    rawStatus: agent.status,
    lastKeepAlive: typeof agent.lastKeepAlive === "string" && Number.isFinite(Date.parse(agent.lastKeepAlive)) ? agent.lastKeepAlive : null,
    registeredAt: typeof agent.dateAdd === "string" && Number.isFinite(Date.parse(agent.dateAdd)) ? agent.dateAdd : null,
    osName: typeof agent.os?.name === "string" ? agent.os.name : null,
    osVersion: typeof agent.os?.version === "string" ? agent.os.version : null,
  };
}

function requireCompleteItems(data) {
  if (!Array.isArray(data.affected_items)
    || asCount(data.total_affected_items) === null
    || data.total_failed_items !== 0
    || !Array.isArray(data.failed_items)
    || data.failed_items.length !== 0) {
    throw new UpstreamError("upstream_incomplete");
  }
  return data;
}

async function readAgentSummary() {
  const payload = await managerGet("/agents/summary", new URLSearchParams({ pretty: "false" }));
  const sourceStatus = payload.data.status;
  if (!sourceStatus || typeof sourceStatus !== "object" || Array.isArray(sourceStatus)) {
    throw new UpstreamError("upstream_invalid_response");
  }
  const status = { active: 0, disconnected: 0, pending: 0, neverConnected: 0, other: 0, total: 0 };
  for (const [rawState, rawCount] of Object.entries(sourceStatus)) {
    const count = asCount(rawCount);
    if (count === null) throw new UpstreamError("upstream_invalid_response");
    if (rawState === "active") status.active = count;
    else if (rawState === "disconnected") status.disconnected = count;
    else if (rawState === "pending") status.pending = count;
    else if (rawState === "never_connected") status.neverConnected = count;
    else status.other += count;
    status.total += count;
  }
  return { source: "wazuh-manager", completeness: "complete", queriedAt: new Date().toISOString(), status };
}

async function readAgents(url) {
  const params = url.searchParams;
  const allowed = new Set(["limit", "offset", "search"]);
  if ([...params.keys()].some((key) => !allowed.has(key)) || [...allowed].some((key) => params.getAll(key).length > 1)) {
    throw new ClientError(400, "invalid_query");
  }
  const limit = parseBoundedInt(params.get("limit"), 25, 1, MAX_LIMIT);
  const offset = parseBoundedInt(params.get("offset"), 0, 0, 100_000);
  const search = (params.get("search") ?? "").trim();
  if (limit === null || offset === null || search.length > 100 || /[\u0000-\u001f\u007f]/.test(search)) {
    throw new ClientError(400, "invalid_query");
  }

  const query = new URLSearchParams({ limit: String(limit), offset: String(offset), select: SELECT_FIELDS, pretty: "false" });
  if (search) query.set("search", search);
  const payload = await managerGet("/agents", query);
  const data = requireCompleteItems(payload.data);
  if (data.affected_items.length > limit) throw new UpstreamError("upstream_invalid_response");

  // The Wazuh manager's built-in agent 000 is shown by GET /agents but is not part of
  // GET /agents/summary. Keep dashboard totals and the asset list on the same scope.
  let managerAgent;
  if (search) {
    const managerQuery = new URLSearchParams({ agents_list: "000", limit: "1", select: "id,name,ip,status,os.name,os.version", pretty: "false" });
    const managerData = requireCompleteItems((await managerGet("/agents", managerQuery)).data);
    managerAgent = managerData.affected_items[0];
  }
  const normalizedSearch = search.toLocaleLowerCase("en-US");
  const managerMatches = search
    ? Boolean(managerAgent && [managerAgent.id, managerAgent.name, managerAgent.ip, managerAgent.status, managerAgent.os?.name, managerAgent.os?.version]
      .some((value) => typeof value === "string" && value.toLocaleLowerCase("en-US").includes(normalizedSearch)))
    : true;

  // On a page after the first, move past manager 000 only when it matched the search.
  // On the first page, remove it in memory and request one extra item if needed.
  let items = data.affected_items.map(parseAgent).filter((agent) => agent.id !== "000");
  let total = data.total_affected_items - (managerMatches ? 1 : 0);
  if (total < 0) throw new UpstreamError("upstream_invalid_response");
  if (managerMatches && offset > 0) {
    const shifted = new URLSearchParams(query);
    shifted.set("offset", String(offset + 1));
    const shiftedData = requireCompleteItems((await managerGet("/agents", shifted)).data);
    items = shiftedData.affected_items.map(parseAgent).filter((agent) => agent.id !== "000");
  } else if (managerMatches && offset === 0 && items.length < limit && data.total_affected_items > data.affected_items.length) {
    const nextPage = new URLSearchParams(query);
    nextPage.set("offset", String(data.affected_items.length));
    const nextData = requireCompleteItems((await managerGet("/agents", nextPage)).data);
    items = [...items, ...nextData.affected_items.map(parseAgent).filter((agent) => agent.id !== "000")].slice(0, limit);
  }

  return {
    source: "wazuh-manager",
    completeness: "complete",
    queriedAt: new Date().toISOString(),
    items,
    page: { limit, offset, total },
  };
}

function parseBoundedInt(value, fallback, min, max) {
  if (value === null) return fallback;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max ? parsed : null;
}

async function readAgentDetail(agentId) {
  if (!/^\d{3,32}$/.test(agentId) || agentId === "000") throw new ClientError(404, "agent_not_found");
  const agentQuery = new URLSearchParams({ agents_list: agentId, limit: "1", select: SELECT_FIELDS, pretty: "false" });
  const agentData = requireCompleteItems((await managerGet("/agents", agentQuery)).data);
  const rawAgent = agentData.affected_items[0];
  if (!rawAgent || rawAgent.id !== agentId) throw new ClientError(404, "agent_not_found");

  const packageData = requireCompleteItems((await managerGet(`/syscollector/${agentId}/packages`, new URLSearchParams({ limit: "1", pretty: "false" }))).data);
  const scanAt = packageData.affected_items[0]?.scan?.time;
  if (typeof scanAt !== "string" || !Number.isFinite(Date.parse(scanAt))) {
    throw new UpstreamError("upstream_incomplete");
  }

  return {
    source: "wazuh-manager",
    completeness: "complete",
    queriedAt: new Date().toISOString(),
    agent: { ...parseAgent(rawAgent), syscollectorScanAt: scanAt },
  };
}

class ClientError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

function isRateLimited(request) {
  const now = Date.now();
  const key = request.socket.remoteAddress ?? "unknown";
  const current = rateBuckets.get(key);
  if (!current || now - current.startedAt >= 60_000) {
    rateBuckets.set(key, { startedAt: now, count: 1 });
    if (rateBuckets.size > 2_000) rateBuckets.clear();
    return false;
  }
  current.count += 1;
  return current.count > 120;
}

function getResponseError(error) {
  if (error instanceof ClientError) return { status: error.status, code: error.code };
  if (error instanceof UpstreamError) {
    if (error.code === "upstream_timeout") return { status: 504, code: "wazuh_timeout" };
    if (error.code === "upstream_auth_failed") return { status: 502, code: "wazuh_authentication_failed" };
    if (error.code === "upstream_incomplete") return { status: 502, code: "wazuh_incomplete_response" };
    return { status: 502, code: "wazuh_unavailable" };
  }
  return { status: 500, code: "internal_error" };
}

const server = createServer(async (request, response) => {
  if (request.url === "/healthz" && request.method === "GET") {
    jsonResponse(response, 200, { status: "ok" });
    return;
  }
  if (request.method !== "GET") {
    jsonResponse(response, 405, { error: "method_not_allowed" });
    return;
  }
  if (!serviceAuthorized(request)) {
    jsonResponse(response, 401, { error: "unauthorized" });
    return;
  }
  if (isRateLimited(request)) {
    jsonResponse(response, 429, { error: "rate_limited" });
    return;
  }

  try {
    const requestUrl = new URL(request.url ?? "/", "http://gateway.invalid");
    const prefix = /^\/v1\/connections\/([A-Za-z0-9._-]{1,80})(\/.*)?$/.exec(requestUrl.pathname);
    if (!prefix || prefix[1] !== config.connectionKey) {
      jsonResponse(response, 404, { error: "connection_not_found" });
      return;
    }
    const route = prefix[2] ?? "";
    if (route === "/agents/summary") {
      if ([...requestUrl.searchParams].length) throw new ClientError(400, "invalid_query");
      jsonResponse(response, 200, await readAgentSummary());
      return;
    }
    if (route === "/agents") {
      jsonResponse(response, 200, await readAgents(requestUrl));
      return;
    }
    const detail = /^\/agents\/([^/]+)$/.exec(route);
    if (detail) {
      if ([...requestUrl.searchParams].length) throw new ClientError(400, "invalid_query");
      let agentId;
      try { agentId = decodeURIComponent(detail[1]); } catch { throw new ClientError(400, "invalid_agent_id"); }
      jsonResponse(response, 200, await readAgentDetail(agentId));
      return;
    }
    jsonResponse(response, 404, { error: "route_not_found" });
  } catch (error) {
    const result = getResponseError(error);
    jsonResponse(response, result.status, { error: result.code });
  }
});

server.headersTimeout = 10_000;
server.requestTimeout = 15_000;
server.listen(PORT, "0.0.0.0");
