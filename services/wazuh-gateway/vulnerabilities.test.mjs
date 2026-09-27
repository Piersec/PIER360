import assert from "node:assert/strict";
import test from "node:test";
import {
  VulnerabilityDataError,
  VulnerabilityQueryError,
  VULNERABILITY_INDEX_PATTERN,
  buildVulnerabilityPageQuery,
  buildVulnerabilitySummaryQuery,
  normalizeVulnerabilityPage,
  normalizeVulnerabilitySummary,
  parseVulnerabilityQuery,
} from "./vulnerabilities.mjs";

function response({ total, buckets = [], hits = [], timedOut = false, failed = 0, relation = "eq", other = 0 }) {
  return {
    timed_out: timedOut,
    _shards: { total: 1, successful: 1 - failed, skipped: 0, failed },
    hits: { total: { value: total, relation }, hits },
    aggregations: { severity_counts: { sum_other_doc_count: other, buckets } },
  };
}

test("summary normalizes the observed Wazuh severity labels and accounts for every document", () => {
  const payload = response({
    total: 99,
    buckets: [
      { key: "High", doc_count: 50 },
      { key: "Medium", doc_count: 32 },
      { key: "Low", doc_count: 7 },
      { key: "Critical", doc_count: 6 },
      { key: "-", doc_count: 4 },
    ],
  });

  assert.deepEqual(normalizeVulnerabilitySummary(payload, "2026-09-27T00:00:00.000Z"), {
    source: "wazuh-indexer",
    completeness: "complete",
    queriedAt: "2026-09-27T00:00:00.000Z",
    total: 99,
    severity: { critical: 6, high: 50, medium: 32, low: 7, unknown: 4 },
  });
});

test("summary counts records without a severity field as unknown", () => {
  const payload = response({
    total: 5,
    buckets: [{ key: "Low", doc_count: 3 }, { key: "Informational", doc_count: 1 }],
  });
  const summary = normalizeVulnerabilitySummary(payload);
  assert.equal(summary.severity.low, 3);
  assert.equal(summary.severity.unknown, 2);
  assert.equal(Object.values(summary.severity).reduce((sum, count) => sum + count, 0), 5);
});

test("summary rejects partial shards, inexact totals, and omitted severity buckets", () => {
  assert.throws(() => normalizeVulnerabilitySummary(response({ total: 1, timedOut: true })), VulnerabilityDataError);
  assert.throws(() => normalizeVulnerabilitySummary(response({ total: 1, failed: 1 })), VulnerabilityDataError);
  assert.throws(() => normalizeVulnerabilitySummary(response({ total: 1, relation: "gte" })), VulnerabilityDataError);
  assert.throws(() => normalizeVulnerabilitySummary(response({ total: 1, other: 1 })), VulnerabilityDataError);
});

test("page maps the observed State document fields and preserves source identity", () => {
  const payload = response({
    total: 1,
    hits: [{
      _index: "wazuh-states-vulnerabilities-mhomolog",
      _id: "005_fingerprint_CVE-2026-35250_3690197",
      _source: {
        agent: { id: "005", name: "host-005", ip: "192.0.2.5" },
        package: { name: "Oracle VirtualBox 7.2.6", version: "7.2.6" },
        vulnerability: {
          id: "CVE-2026-35250",
          severity: "Low",
          score: { base: 2.3, version: "3.1" },
          detected_at: "2026-08-12T15:30:47.933Z",
        },
      },
    }],
  });
  const page = normalizeVulnerabilityPage(payload, { limit: 25, offset: 0 }, "2026-09-27T00:00:00.000Z");
  assert.deepEqual(page.items[0], {
    findingKey: "wazuh-states-vulnerabilities-mhomolog:005_fingerprint_CVE-2026-35250_3690197",
    agentId: "005",
    agentName: "host-005",
    agentIp: "192.0.2.5",
    cve: "CVE-2026-35250",
    packageName: "Oracle VirtualBox 7.2.6",
    packageVersion: "7.2.6",
    severity: "low",
    cvssScore: 2.3,
    detectedAt: "2026-08-12T15:30:47.933Z",
  });
  assert.equal(page.page.total, 1);
});

test("page maps absent and dash severities to unknown and tolerates absent optional source fields", () => {
  const payload = response({
    total: 2,
    hits: [
      { _index: "index-a", _id: "one", _source: { vulnerability: { severity: "-" } } },
      { _index: "index-b", _id: "two", _source: {} },
    ],
  });
  const page = normalizeVulnerabilityPage(payload, { limit: 25, offset: 0 });
  assert.deepEqual(page.items.map((item) => item.severity), ["unknown", "unknown"]);
  assert.equal(page.items[0].agentIp, null);
  assert.equal(page.items[1].cvssScore, null);
});

test("query parsing rejects arbitrary parameters, repeated parameters, and offsets beyond the Indexer window", () => {
  assert.throws(() => parseVulnerabilityQuery(new URLSearchParams("index=*&q=bad")), VulnerabilityQueryError);
  assert.throws(() => parseVulnerabilityQuery(new URLSearchParams("limit=10&limit=20")), VulnerabilityQueryError);
  assert.throws(() => parseVulnerabilityQuery(new URLSearchParams("offset=9999&limit=25")), VulnerabilityQueryError);
  assert.throws(() => parseVulnerabilityQuery(new URLSearchParams("severity=anything")), VulnerabilityQueryError);
});

test("page query only targets fixed fields and adds typed search and severity filters", () => {
  const query = buildVulnerabilityPageQuery(parseVulnerabilityQuery(
    new URLSearchParams("limit=10&offset=20&search=CVE-2026&severity=high"),
  ));
  assert.equal(VULNERABILITY_INDEX_PATTERN, "wazuh-states-vulnerabilities-*");
  assert.equal(query.from, 20);
  assert.equal(query.size, 10);
  assert.deepEqual(query.query.bool.filter, [{ terms: { "vulnerability.severity": ["High", "high", "HIGH"] } }]);
  assert.equal(query.query.bool.must[0].multi_match.query, "CVE-2026");
  assert.ok(!("index" in query));

  const unknown = buildVulnerabilityPageQuery({ limit: 10, offset: 0, severity: "unknown" });
  assert.deepEqual(unknown.query.bool.must_not, [{ terms: { "vulnerability.severity": [
    "Critical", "critical", "CRITICAL", "High", "high", "HIGH", "Medium", "medium", "MEDIUM", "Low", "low", "LOW",
  ] } }]);
});

test("summary query requests exact hits and a bounded severity aggregation", () => {
  assert.deepEqual(buildVulnerabilitySummaryQuery(), {
    size: 0,
    track_total_hits: true,
    aggs: { severity_counts: { terms: { field: "vulnerability.severity", size: 100 } } },
  });
});
