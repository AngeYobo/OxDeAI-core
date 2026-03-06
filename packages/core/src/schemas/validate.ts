import type { VerificationViolation } from "../verification/types.js";

export type SchemaValidationIssue = {
  path: string;
  code: "TYPE" | "REQUIRED" | "ENUM" | "FORMAT" | "ADDITIONAL" | "VALUE";
  message: string;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hex64(value: unknown): boolean {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function intNonNegative(value: unknown): boolean {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function bigintLike(value: unknown): boolean {
  return typeof value === "number" && Number.isInteger(value) || typeof value === "string" && /^-?[0-9]+n?$/.test(value);
}

function pushAdditional(obj: Record<string, unknown>, allowed: readonly string[], path: string, issues: SchemaValidationIssue[]): void {
  const allowedSet = new Set(allowed);
  const extras = Object.keys(obj).filter((k) => !allowedSet.has(k)).sort();
  for (const key of extras) {
    issues.push({ path: `${path}.${key}`, code: "ADDITIONAL", message: "unknown field" });
  }
}

function sorted(issues: SchemaValidationIssue[]): SchemaValidationIssue[] {
  return [...issues].sort((a, b) => {
    if (a.path < b.path) return -1;
    if (a.path > b.path) return 1;
    if (a.code < b.code) return -1;
    if (a.code > b.code) return 1;
    return a.message < b.message ? -1 : a.message > b.message ? 1 : 0;
  });
}

export function validateCanonicalStateJson(value: unknown): SchemaValidationIssue[] {
  const issues: SchemaValidationIssue[] = [];
  if (!isObject(value)) return [{ path: "$", code: "TYPE", message: "must be object" }];

  const required = ["formatVersion", "engineVersion", "policyId", "modules"] as const;
  for (const key of required) {
    if (!(key in value)) issues.push({ path: `$`, code: "REQUIRED", message: `missing ${key}` });
  }
  pushAdditional(value, required, "$", issues);

  if ("formatVersion" in value && value.formatVersion !== 1) {
    issues.push({ path: "$.formatVersion", code: "VALUE", message: "must equal 1" });
  }
  if ("engineVersion" in value && typeof value.engineVersion !== "string") {
    issues.push({ path: "$.engineVersion", code: "TYPE", message: "must be string" });
  }
  if ("policyId" in value && (typeof value.policyId !== "string" || value.policyId.length === 0)) {
    issues.push({ path: "$.policyId", code: "TYPE", message: "must be non-empty string" });
  }
  if ("modules" in value && !isObject(value.modules)) {
    issues.push({ path: "$.modules", code: "TYPE", message: "must be object" });
  }

  return sorted(issues);
}

export function validateAuthorizationJson(value: unknown): SchemaValidationIssue[] {
  const issues: SchemaValidationIssue[] = [];
  if (!isObject(value)) return [{ path: "$", code: "TYPE", message: "must be object" }];

  const required = [
    "authorization_id",
    "auth_id",
    "issuer",
    "audience",
    "intent_hash",
    "state_hash",
    "policy_id",
    "policy_version",
    "state_snapshot_hash",
    "decision",
    "issued_at",
    "expiry",
    "expires_at",
    "engine_signature"
  ] as const;
  for (const key of required) {
    if (!(key in value)) issues.push({ path: "$", code: "REQUIRED", message: `missing ${key}` });
  }
  const allowed = [...required, "nonce", "capability", "signature"] as const;
  pushAdditional(value, allowed, "$", issues);

  if ("auth_id" in value && (typeof value.auth_id !== "string" || value.auth_id.length === 0)) issues.push({ path: "$.auth_id", code: "TYPE", message: "must be non-empty string" });
  if ("issuer" in value && (typeof value.issuer !== "string" || value.issuer.length === 0)) issues.push({ path: "$.issuer", code: "TYPE", message: "must be non-empty string" });
  if ("audience" in value && (typeof value.audience !== "string" || value.audience.length === 0)) issues.push({ path: "$.audience", code: "TYPE", message: "must be non-empty string" });
  if ("authorization_id" in value && !hex64(value.authorization_id)) issues.push({ path: "$.authorization_id", code: "FORMAT", message: "must be 64-char lowercase hex" });
  if ("intent_hash" in value && !hex64(value.intent_hash)) issues.push({ path: "$.intent_hash", code: "FORMAT", message: "must be 64-char lowercase hex" });
  if ("state_hash" in value && !hex64(value.state_hash)) issues.push({ path: "$.state_hash", code: "FORMAT", message: "must be 64-char lowercase hex" });
  if ("policy_id" in value && !hex64(value.policy_id)) issues.push({ path: "$.policy_id", code: "FORMAT", message: "must be 64-char lowercase hex" });
  if ("policy_version" in value && typeof value.policy_version !== "string") issues.push({ path: "$.policy_version", code: "TYPE", message: "must be string" });
  if ("state_snapshot_hash" in value && !hex64(value.state_snapshot_hash)) issues.push({ path: "$.state_snapshot_hash", code: "FORMAT", message: "must be 64-char lowercase hex" });
  if ("decision" in value && value.decision !== "ALLOW" && value.decision !== "DENY") issues.push({ path: "$.decision", code: "ENUM", message: "must be ALLOW or DENY" });
  if ("issued_at" in value && !intNonNegative(value.issued_at)) issues.push({ path: "$.issued_at", code: "TYPE", message: "must be non-negative integer" });
  if ("expiry" in value && !intNonNegative(value.expiry)) issues.push({ path: "$.expiry", code: "TYPE", message: "must be non-negative integer" });
  if ("expires_at" in value && !intNonNegative(value.expires_at)) issues.push({ path: "$.expires_at", code: "TYPE", message: "must be non-negative integer" });
  if ("engine_signature" in value && !hex64(value.engine_signature)) issues.push({ path: "$.engine_signature", code: "FORMAT", message: "must be 64-char lowercase hex" });
  if ("signature" in value && value.signature !== undefined && typeof value.signature !== "string") issues.push({ path: "$.signature", code: "TYPE", message: "must be string when present" });
  return sorted(issues);
}

export function validateIntentJson(value: unknown): SchemaValidationIssue[] {
  const issues: SchemaValidationIssue[] = [];
  if (!isObject(value)) return [{ path: "$", code: "TYPE", message: "must be object" }];

  const commonRequired = [
    "intent_id",
    "agent_id",
    "action_type",
    "amount",
    "target",
    "timestamp",
    "metadata_hash",
    "nonce",
    "signature"
  ] as const;

  for (const key of commonRequired) {
    if (!(key in value)) issues.push({ path: "$", code: "REQUIRED", message: `missing ${key}` });
  }

  const typeValue = value.type;
  if (typeValue !== undefined && typeValue !== "EXECUTE" && typeValue !== "RELEASE") {
    issues.push({ path: "$.type", code: "ENUM", message: "must be EXECUTE or RELEASE" });
  }
  if (typeValue === "RELEASE" && (typeof value.authorization_id !== "string" || value.authorization_id.length === 0)) {
    issues.push({ path: "$.authorization_id", code: "REQUIRED", message: "required for RELEASE" });
  }

  if ("action_type" in value && !["PAYMENT", "PURCHASE", "PROVISION", "ONCHAIN_TX"].includes(String(value.action_type))) {
    issues.push({ path: "$.action_type", code: "ENUM", message: "invalid action_type" });
  }
  if ("amount" in value && !bigintLike(value.amount)) issues.push({ path: "$.amount", code: "TYPE", message: "must be integer/bigint-like string" });
  if ("nonce" in value && !bigintLike(value.nonce)) issues.push({ path: "$.nonce", code: "TYPE", message: "must be integer/bigint-like string" });
  if ("timestamp" in value && !intNonNegative(value.timestamp)) issues.push({ path: "$.timestamp", code: "TYPE", message: "must be non-negative integer" });
  if ("depth" in value && !intNonNegative(value.depth)) issues.push({ path: "$.depth", code: "TYPE", message: "must be non-negative integer" });

  const allowed = [
    ...commonRequired,
    "asset",
    "depth",
    "type",
    "authorization_id",
    "tool",
    "tool_call"
  ] as const;
  pushAdditional(value, allowed, "$", issues);
  return sorted(issues);
}

export function validateAuditEventJson(value: unknown): SchemaValidationIssue[] {
  const issues: SchemaValidationIssue[] = [];
  if (!isObject(value)) return [{ path: "$", code: "TYPE", message: "must be object" }];

  if (!("type" in value) || typeof value.type !== "string") {
    issues.push({ path: "$.type", code: "REQUIRED", message: "missing type" });
    return issues;
  }
  if (!("timestamp" in value) || !intNonNegative(value.timestamp)) {
    issues.push({ path: "$.timestamp", code: "TYPE", message: "timestamp must be non-negative integer" });
  }
  if ("policyId" in value && typeof value.policyId !== "string") {
    issues.push({ path: "$.policyId", code: "TYPE", message: "policyId must be string" });
  }

  const t = value.type;
  if (t === "INTENT_RECEIVED") {
    const req = ["type", "intent_hash", "agent_id", "timestamp", "policyId"] as const;
    if (typeof value.intent_hash !== "string" || value.intent_hash.length === 0) issues.push({ path: "$.intent_hash", code: "TYPE", message: "must be non-empty string" });
    if (typeof value.agent_id !== "string") issues.push({ path: "$.agent_id", code: "TYPE", message: "must be string" });
    pushAdditional(value, req, "$", issues);
  } else if (t === "DECISION") {
    const req = ["type", "intent_hash", "decision", "reasons", "policy_version", "timestamp", "policyId"] as const;
    if (typeof value.intent_hash !== "string" || value.intent_hash.length === 0) issues.push({ path: "$.intent_hash", code: "TYPE", message: "must be non-empty string" });
    if (value.decision !== "ALLOW" && value.decision !== "DENY") issues.push({ path: "$.decision", code: "ENUM", message: "must be ALLOW or DENY" });
    if (!Array.isArray(value.reasons) || !value.reasons.every((r) => typeof r === "string")) issues.push({ path: "$.reasons", code: "TYPE", message: "must be string array" });
    if (typeof value.policy_version !== "string") issues.push({ path: "$.policy_version", code: "TYPE", message: "must be string" });
    pushAdditional(value, req, "$", issues);
  } else if (t === "AUTH_EMITTED") {
    const req = ["type", "authorization_id", "intent_hash", "expires_at", "timestamp", "policyId"] as const;
    if (typeof value.authorization_id !== "string" || value.authorization_id.length === 0) issues.push({ path: "$.authorization_id", code: "TYPE", message: "must be non-empty string" });
    if (typeof value.intent_hash !== "string" || value.intent_hash.length === 0) issues.push({ path: "$.intent_hash", code: "TYPE", message: "must be non-empty string" });
    if (!intNonNegative(value.expires_at)) issues.push({ path: "$.expires_at", code: "TYPE", message: "must be non-negative integer" });
    pushAdditional(value, req, "$", issues);
  } else if (t === "EXECUTION_ATTESTED") {
    const req = ["type", "intent_hash", "execution_ref", "timestamp", "policyId"] as const;
    if (typeof value.intent_hash !== "string" || value.intent_hash.length === 0) issues.push({ path: "$.intent_hash", code: "TYPE", message: "must be non-empty string" });
    if (typeof value.execution_ref !== "string") issues.push({ path: "$.execution_ref", code: "TYPE", message: "must be string" });
    pushAdditional(value, req, "$", issues);
  } else if (t === "STATE_CHECKPOINT") {
    const req = ["type", "stateHash", "timestamp", "policyId"] as const;
    if (typeof value.stateHash !== "string" || value.stateHash.length === 0) issues.push({ path: "$.stateHash", code: "TYPE", message: "must be non-empty string" });
    pushAdditional(value, req, "$", issues);
  } else {
    issues.push({ path: "$.type", code: "ENUM", message: "unsupported event type" });
  }

  return sorted(issues);
}

export function validateAuditLogJson(value: unknown): SchemaValidationIssue[] {
  const issues: SchemaValidationIssue[] = [];
  if (!Array.isArray(value)) return [{ path: "$", code: "TYPE", message: "must be array" }];
  for (let i = 0; i < value.length; i++) {
    for (const issue of validateAuditEventJson(value[i])) {
      issues.push({ ...issue, path: issue.path.replace("$", `$[${i}]`) });
    }
  }
  return sorted(issues);
}

export function validateVerificationEnvelopeWireJson(value: unknown): SchemaValidationIssue[] {
  const issues: SchemaValidationIssue[] = [];
  if (!isObject(value)) return [{ path: "$", code: "TYPE", message: "must be object" }];

  const required = ["formatVersion", "snapshot", "events"] as const;
  for (const key of required) {
    if (!(key in value)) issues.push({ path: "$", code: "REQUIRED", message: `missing ${key}` });
  }
  pushAdditional(value, required, "$", issues);

  if ("formatVersion" in value && value.formatVersion !== 1) {
    issues.push({ path: "$.formatVersion", code: "VALUE", message: "must equal 1" });
  }
  if ("snapshot" in value && (typeof value.snapshot !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value.snapshot))) {
    issues.push({ path: "$.snapshot", code: "FORMAT", message: "must be base64 string" });
  }
  if ("events" in value && !Array.isArray(value.events)) {
    issues.push({ path: "$.events", code: "TYPE", message: "must be array" });
  } else if (Array.isArray(value.events)) {
    for (let i = 0; i < value.events.length; i++) {
      for (const issue of validateAuditEventJson(value.events[i])) {
        issues.push({ ...issue, path: issue.path.replace("$", `$.events[${i}]`) });
      }
    }
  }

  return sorted(issues);
}

export function validateVerificationResultJson(value: unknown): SchemaValidationIssue[] {
  const issues: SchemaValidationIssue[] = [];
  if (!isObject(value)) return [{ path: "$", code: "TYPE", message: "must be object" }];
  const required = ["ok", "status", "violations"] as const;
  for (const key of required) {
    if (!(key in value)) issues.push({ path: "$", code: "REQUIRED", message: `missing ${key}` });
  }

  if ("ok" in value && typeof value.ok !== "boolean") issues.push({ path: "$.ok", code: "TYPE", message: "must be boolean" });
  if ("status" in value && !["ok", "invalid", "inconclusive"].includes(String(value.status))) {
    issues.push({ path: "$.status", code: "ENUM", message: "invalid status" });
  }
  if ("violations" in value && !Array.isArray(value.violations)) {
    issues.push({ path: "$.violations", code: "TYPE", message: "must be array" });
  }
  return sorted(issues);
}

export function mapIssuesToViolation(code: VerificationViolation["code"], issues: readonly SchemaValidationIssue[], index?: number): VerificationViolation[] {
  return issues.map((issue) => ({
    code,
    index,
    message: `${issue.path}: ${issue.message}`
  }));
}
