#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Security advisory gate: fails when audit findings lack a valid, non-expired
 * exception.
 *
 * This is freshness-dependent evidence: the external advisory database can
 * change while the commit and lockfile stay the same, so the same input can
 * produce a different decision on a later run. It is deliberately separate
 * from the reproducible policy-boundary check (`pnpm run security:policy-boundary`),
 * which depends only on repo state and inputs. Do not reintroduce that
 * harness here; run it as its own CI check instead.
 *
 * Usage: node scripts/security-gate.mjs audit.json security/vuln-policy.json
 */
import fs from "node:fs";
import crypto from "node:crypto";

const args = process.argv.slice(2);
const [auditPath, policyPath] = args.filter((a) => !a.startsWith("--"));
const artifactOut = args.find((a) => a.startsWith("--artifact-out="))?.split("=", 2)[1] ?? null;

if (!auditPath || !policyPath) {
  console.error(
    "Usage: node scripts/security-gate.mjs <audit.json> <vuln-policy.json> [--artifact-out=path]"
  );
  process.exit(2);
}

const loadJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const audit = loadJson(auditPath);
const policy = loadJson(policyPath);
const exceptions = policy.exceptions ?? [];
const rules = policy.rules ?? {
  critical: "deny",
  high: "deny",
  moderate: "require_exception",
  medium: "require_exception",
  low: "warn"
};

const today = new Date();
today.setHours(0, 0, 0, 0);

const isExpired = (dateStr) => {
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return true;
  d.setHours(0, 0, 0, 0);
  return d < today;
};

// Normalize pnpm audit JSON (fallback to npm advisories shape)
function normalizeFindings(a) {
  const findings = [];

  if (Array.isArray(a.vulnerabilities)) {
    for (const v of a.vulnerabilities) {
      findings.push({
        id: v.id ?? v.name ?? v.title ?? `${v.package}@${v.version}`,
        package: v.package ?? v.name,
        severity: (v.severity ?? v.severityLevel ?? "").toLowerCase(),
        path: v.path ?? (Array.isArray(v.via) ? v.via.join(" > ") : "") ?? "",
      });
    }
  } else if (a.advisories) {
    for (const key of Object.keys(a.advisories)) {
      const adv = a.advisories[key];
      findings.push({
        id: adv.id ?? key,
        package: adv.module_name,
        severity: (adv.severity ?? "").toLowerCase(),
        path: adv.findings?.[0]?.paths?.[0] ?? "",
      });
    }
  }

  return findings;
}

const findings = normalizeFindings(audit);

const normSeverity = (s) => {
  const val = (s ?? "").toLowerCase();
  return val === "medium" ? "moderate" : val;
};

const stableStringify = (value) => {
  const sorter = (v) => {
    if (Array.isArray(v)) return v.map(sorter);
    if (v && typeof v === "object") {
      return Object.keys(v)
        .sort()
        .reduce((acc, k) => {
          acc[k] = sorter(v[k]);
          return acc;
        }, {});
    }
    return v;
  };
  return JSON.stringify(sorter(value));
};

const sha256 = (v) => crypto.createHash("sha256").update(stableStringify(v)).digest("hex");

function matchException(f) {
  return exceptions.find((ex) => {
    const severityMatch = normSeverity(ex.severity) === normSeverity(f.severity);
    const idMatch = ex.id ? ex.id === f.id : true;
    const pkgMatch = ex.package ? ex.package === f.package : true;
    return severityMatch && idMatch && pkgMatch;
  });
}

const blocking = [];
const matched = [];
const expired = [];
const warnings = [];

for (const f of findings) {
  const sev = normSeverity(f.severity);
  const ex = matchException(f);

  if (ex && isExpired(ex.expires_on)) {
    expired.push({ finding: f, exception: ex });
  }

  const hasValidEx =
    !!ex &&
    !isExpired(ex.expires_on) &&
    !!ex.reason &&
    normSeverity(ex.severity) === sev;

  if (hasValidEx) matched.push({ finding: f, exception: ex });

  // policy-driven action, fail-closed if missing
  let action = rules[sev] ?? "deny";
  // enforce invariant: high/critical always deny
  if (sev === "high" || sev === "critical") action = "deny";

  if (action === "deny") {
    blocking.push({ finding: f, exception: ex, reason: "policy denies this severity" });
  } else if (action === "require_exception") {
    if (!hasValidEx) {
      blocking.push({
        finding: f,
        exception: ex,
        reason: "moderate vulnerability without valid, non-expired exception"
      });
    }
  } else if (action === "warn") {
    warnings.push(f);
  } else {
    blocking.push({ finding: f, exception: ex, reason: `unknown action '${action}'` });
  }
}

const fmt = (f) =>
  `${f.severity || "unknown"} | ${f.package || "?"} | id=${f.id || "?"} | path=${f.path || "-"}`;

console.log("== Security Advisory Gate ==");
console.log(`Findings: ${findings.length}`);
console.log(`Blocking: ${blocking.length}`);
console.log(`Matched exceptions: ${matched.length}`);
console.log(`Expired exceptions: ${expired.length}`);
console.log(`Warnings: ${warnings.length}`);

if (blocking.length) {
  console.log("\nBlocking findings:");
  for (const b of blocking) console.log(` - ${fmt(b.finding)} (${b.reason})`);
}

if (expired.length) {
  console.log("\nExpired exceptions:");
  for (const e of expired) console.log(` - ${fmt(e.finding)} | exception expires_on=${e.exception.expires_on}`);
}

if (!exceptions.length) console.log("\nNo exceptions configured.");

const ok = blocking.length === 0 && expired.length === 0;
const decision = ok ? "ALLOW" : "DENY";
const reason = ok
  ? "no blocking findings"
  : blocking[0]
  ? blocking[0].reason
  : expired[0]
  ? "expired exception"
  : "unknown reason";

console.log(`\nDecision: ${decision}`);
console.log(`Reason: ${reason}`);

if (artifactOut) {
  const policyHash = sha256(rules);
  const exceptionsHash = sha256(exceptions);
  const findingsHash = sha256(findings);
  const inputHash = sha256({ policyHash, exceptionsHash, findingsHash, decision, reason });

  const artifact = {
    formatVersion: 1,
    type: "SecurityGateDecision",
    decision,
    reason,
    timestamp: new Date().toISOString(),
    policyHash,
    exceptionsHash,
    findingsHash,
    inputHash
  };

  const artifactHash = sha256(artifact);
  artifact.artifactHash = artifactHash;

  fs.writeFileSync(artifactOut, stableStringify(artifact) + "\n", "utf8");
  console.log(`Artifact written to ${artifactOut}`);
}

process.exit(ok ? 0 : 1);
