export const VULNERABILITY_INDEX_PATTERN = "wazuh-states-vulnerabilities-*";
export const MAX_VULNERABILITY_LIMIT = 100;
export const MAX_VULNERABILITY_OFFSET = 9_999;

const CANONICAL_SEVERITIES = ["critical", "high", "medium", "low", "unknown"];
const SEVERITY_FIELD = "vulnerability.severity";
const SEARCH_FIELDS = [
  "vulnerability.id",
  "package.name",
  "package.version",
  "agent.name",
  "agent.id",
  "agent.ip",
];
const SOURCE_FIELDS = [
  "agent.id",
  "agent.name",
  "agent.ip",
  "host.ip",
  "package.name",
  "package.version",
  "vulnerability.id",
  "vulnerability.severity",
  "vulnerability.score.base",
  "vulnerability.detected_at",
];

const SEVERITY_TERMS = {
  critical: ["Critical", "critical", "CRITICAL"],
  high: ["High", "high", "HIGH"],
  medium: ["Medium", "medium", "MEDIUM"],
  low: ["Low", "low", "LOW"],
};
const ALL_KNOWN_SEVERITY_TERMS = [...new Set(Object.values(SEVERITY_TERMS).flat())];

export class VulnerabilityQueryError extends Error {
  constructor(code = "invalid_query") {
    super(code);
    this.name = "VulnerabilityQueryError";
    this.code = code;
  }
}

export class VulnerabilityDataError extends Error {
  constructor(code) {
    super(code);
    this.name = "VulnerabilityDataError";
    this.code = code;
  }
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function boundedInt(value, fallback, min, max) {
  if (value === null) return fallback;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max ? parsed : null;
}

export function parseVulnerabilityQuery(searchParams) {
  const allowed = new Set(["limit", "offset", "search", "severity"]);
  if ([...searchParams.keys()].some((key) => !allowed.has(key))
    || [...allowed].some((key) => searchParams.getAll(key).length > 1)) {
    throw new VulnerabilityQueryError();
  }

  const limit = boundedInt(searchParams.get("limit"), 25, 1, MAX_VULNERABILITY_LIMIT);
  const offset = boundedInt(searchParams.get("offset"), 0, 0, MAX_VULNERABILITY_OFFSET);
  const search = (searchParams.get("search") ?? "").trim();
  const severity = searchParams.get("severity") ?? "";
  if (limit === null || offset === null || offset + limit > 10_000
    || search.length > 100 || /[\u0000-\u001f\u007f]/.test(search)
    || (severity !== "" && !CANONICAL_SEVERITIES.includes(severity))) {
    throw new VulnerabilityQueryError();
  }

  return { limit, offset, search, severity: severity || undefined };
}

export function buildVulnerabilitySummaryQuery() {
  return {
    size: 0,
    track_total_hits: true,
    aggs: {
      severity_counts: {
        terms: { field: SEVERITY_FIELD, size: 100 },
      },
    },
  };
}

export function buildVulnerabilityPageQuery({ limit, offset, search = "", severity }) {
  const bool = { must: [] };
  if (search) {
    bool.must.push({
      multi_match: {
        query: search,
        type: "phrase_prefix",
        fields: SEARCH_FIELDS,
      },
    });
  } else {
    bool.must.push({ match_all: {} });
  }

  if (severity === "unknown") {
    bool.must_not = [{ terms: { [SEVERITY_FIELD]: ALL_KNOWN_SEVERITY_TERMS } }];
  } else if (severity) {
    bool.filter = [{ terms: { [SEVERITY_FIELD]: SEVERITY_TERMS[severity] } }];
  }

  return {
    from: offset,
    size: limit,
    track_total_hits: true,
    _source: SOURCE_FIELDS,
    query: { bool },
  };
}

function exactTotal(payload) {
  const shards = payload?._shards;
  if (payload?.timed_out !== false || !shards || count(shards.total) === null || shards.total < 1
    || count(shards.successful) === null || count(shards.failed) !== 0
    || count(shards.skipped ?? 0) === null
    || shards.successful + (shards.skipped ?? 0) !== shards.total) {
    throw new VulnerabilityDataError("upstream_incomplete");
  }

  const rawTotal = payload?.hits?.total;
  if (typeof rawTotal === "number") {
    const numericTotal = count(rawTotal);
    if (numericTotal === null) throw new VulnerabilityDataError("upstream_invalid_response");
    return numericTotal;
  }
  if (!rawTotal || typeof rawTotal !== "object" || rawTotal.relation !== "eq") {
    throw new VulnerabilityDataError("upstream_incomplete");
  }
  const total = count(rawTotal.value);
  if (total === null) throw new VulnerabilityDataError("upstream_invalid_response");
  return total;
}

export function normalizeVulnerabilitySummary(payload, queriedAt = new Date().toISOString()) {
  const total = exactTotal(payload);
  const buckets = payload?.aggregations?.severity_counts?.buckets;
  const omittedCount = count(payload?.aggregations?.severity_counts?.sum_other_doc_count);
  if (!Array.isArray(buckets) || omittedCount === null || omittedCount > 0) {
    throw new VulnerabilityDataError("upstream_incomplete");
  }

  const severity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  let bucketTotal = 0;
  for (const bucket of buckets) {
    if (!bucket || typeof bucket.key !== "string" || count(bucket.doc_count) === null) {
      throw new VulnerabilityDataError("upstream_invalid_response");
    }
    bucketTotal += bucket.doc_count;
    if (bucketTotal > total) throw new VulnerabilityDataError("upstream_invalid_response");
    severity[normalizeSeverity(bucket.key)] += bucket.doc_count;
  }

  // Missing severity fields are still records. Count them as unknown rather than dropping them.
  severity.unknown += total - bucketTotal;
  if (Object.values(severity).reduce((sum, value) => sum + value, 0) !== total) {
    throw new VulnerabilityDataError("upstream_invalid_response");
  }
  return { source: "wazuh-indexer", completeness: "complete", queriedAt, total, severity };
}

export function normalizeVulnerabilityPage(payload, page, queriedAt = new Date().toISOString()) {
  const total = exactTotal(payload);
  const hits = payload?.hits?.hits;
  if (!Array.isArray(hits) || hits.length > page.limit) {
    throw new VulnerabilityDataError("upstream_invalid_response");
  }
  const items = hits.map(normalizeFinding);
  return {
    source: "wazuh-indexer",
    completeness: "complete",
    queriedAt,
    items,
    page: { limit: page.limit, offset: page.offset, total },
  };
}

function normalizeFinding(hit) {
  if (!hit || typeof hit !== "object" || typeof hit._index !== "string" || typeof hit._id !== "string"
    || !hit._index || !hit._id || !hit._source || typeof hit._source !== "object") {
    throw new VulnerabilityDataError("upstream_invalid_response");
  }
  const findingKey = `${hit._index}:${hit._id}`;
  if (findingKey.length > 512 || /[\u0000-\u001f\u007f]/.test(findingKey)) {
    throw new VulnerabilityDataError("upstream_invalid_response");
  }

  const source = hit._source;
  const vulnerability = source.vulnerability && typeof source.vulnerability === "object" ? source.vulnerability : {};
  const packageInfo = source.package && typeof source.package === "object" ? source.package : {};
  const agent = source.agent && typeof source.agent === "object" ? source.agent : {};
  const score = vulnerability.score && typeof vulnerability.score === "object"
    ? vulnerability.score.base
    : vulnerability.score;

  return {
    findingKey,
    agentId: nullableString(agent.id),
    agentName: nullableString(agent.name),
    agentIp: nullableString(agent.ip) ?? nullableString(source.host?.ip),
    cve: nullableString(vulnerability.id),
    packageName: nullableString(packageInfo.name),
    packageVersion: nullableString(packageInfo.version),
    severity: normalizeSeverity(vulnerability.severity),
    cvssScore: normalizeScore(score),
    detectedAt: validDate(vulnerability.detected_at),
  };
}

function normalizeSeverity(value) {
  if (typeof value !== "string") return "unknown";
  const normalized = value.trim().toLowerCase();
  if (normalized === "critical") return "critical";
  if (normalized === "high") return "high";
  if (normalized === "medium") return "medium";
  if (normalized === "low") return "low";
  return "unknown";
}

function nullableString(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function normalizeScore(value) {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= 10 ? parsed : null;
}

function validDate(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) ? value : null;
}
