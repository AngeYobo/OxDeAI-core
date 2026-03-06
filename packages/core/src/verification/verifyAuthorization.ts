import type { AuthorizationV1 } from "../types/authorization.js";
import type { VerificationResult, VerificationViolation } from "./types.js";

/** @public */
export type VerifyAuthorizationOptions = {
  now?: number;
  expectedIssuer?: string;
  expectedAudience?: string;
  expectedPolicyId?: string;
  consumedAuthIds?: readonly string[];
};

function sortViolations(violations: VerificationViolation[]): VerificationViolation[] {
  return [...violations].sort((a, b) => {
    if (a.code < b.code) return -1;
    if (a.code > b.code) return 1;
    return (a.index ?? 0) - (b.index ?? 0);
  });
}

function hasText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function nowOrThrow(now: number | undefined): number {
  if (now !== undefined) return now;
  return Math.floor(Date.now() / 1000);
}

/** @public */
export function verifyAuthorization(
  auth: AuthorizationV1,
  opts?: VerifyAuthorizationOptions
): VerificationResult {
  const violations: VerificationViolation[] = [];
  const now = nowOrThrow(opts?.now);
  const consumed = new Set(opts?.consumedAuthIds ?? []);

  if (!hasText(auth.decision) || auth.decision !== "ALLOW") {
    violations.push({ code: "AUTH_DECISION_INVALID", message: "authorization decision must be ALLOW" });
  }
  if (!hasText(auth.intent_hash)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "intent_hash is required" });
  }
  if (!hasText(auth.state_hash)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "state_hash is required" });
  }
  if (!hasText(auth.policy_id)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "policy_id is required" });
  }
  if (!hasText(auth.issuer)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "issuer is required" });
  }
  if (!hasText(auth.audience)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "audience is required" });
  }
  if (!hasText(auth.auth_id)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "auth_id is required" });
  }

  if (!Number.isInteger(auth.expiry)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "expiry must be integer unix seconds" });
  } else if (now >= auth.expiry) {
    violations.push({ code: "AUTH_EXPIRED", message: "authorization has expired" });
  }

  if (opts?.expectedIssuer !== undefined && auth.issuer !== opts.expectedIssuer) {
    violations.push({ code: "AUTH_ISSUER_MISMATCH", message: "issuer does not match expectedIssuer" });
  }
  if (opts?.expectedAudience !== undefined && auth.audience !== opts.expectedAudience) {
    violations.push({ code: "AUTH_AUDIENCE_MISMATCH", message: "audience does not match expectedAudience" });
  }
  if (opts?.expectedPolicyId !== undefined && auth.policy_id !== opts.expectedPolicyId) {
    violations.push({ code: "AUTH_POLICY_ID_MISMATCH", message: "policy_id does not match expectedPolicyId" });
  }
  if (hasText(auth.auth_id) && consumed.has(auth.auth_id)) {
    violations.push({ code: "AUTH_REPLAY", message: "auth_id has already been consumed" });
  }

  if (violations.length > 0) {
    return {
      ok: false,
      status: "invalid",
      violations: sortViolations(violations),
      policyId: hasText(auth.policy_id) ? auth.policy_id : undefined,
      stateHash: hasText(auth.state_hash) ? auth.state_hash : undefined
    };
  }

  return {
    ok: true,
    status: "ok",
    violations: [],
    policyId: auth.policy_id,
    stateHash: auth.state_hash
  };
}
