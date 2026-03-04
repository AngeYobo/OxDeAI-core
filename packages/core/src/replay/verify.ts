import { createHash } from "node:crypto";
import { canonicalJson } from "../crypto/hashes.js";
import type { AuditEntry } from "../audit/AuditLog.js";

/** @public */
export type VerifyStatus = "ok" | "violation" | "inconclusive";

/** @public */
export type VerifyViolation = {
  code: string;
  at?: number;
  detail?: string;
};

/** @public */
export type VerifyOptions = {
  policyId?: string;
  mode?: "strict" | "best-effort";
};

/** @public */
export type VerifyResult = {
  ok: boolean;
  status: VerifyStatus;
  violations: VerifyViolation[];
  expectedPolicyId?: string;
  observedPolicyId?: string;
  auditHeadHash?: string;
};

function canonicalizeEntry(event: AuditEntry): Uint8Array {
  const normalized = {
    ...event,
    policyId: event.policyId ?? null
  };
  return new TextEncoder().encode(canonicalJson(normalized));
}

function computeNextHash(prev: string, event: AuditEntry): string {
  const canonical = canonicalizeEntry(event);
  return createHash("sha256")
    .update(prev, "utf8")
    .update("\n", "utf8")
    .update(canonical)
    .digest("hex");
}

/** @public */
export function verifyReplayEvents(events: readonly AuditEntry[], opts?: VerifyOptions): VerifyResult {
  const mode = opts?.mode ?? "strict";
  const violations: VerifyViolation[] = [];
  let checkpointCount = 0;
  const stateHashRe = /^[0-9a-f]{64}$/;

  let head = "GENESIS";
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (i > 0 && e.timestamp < events[i - 1].timestamp) {
      violations.push({ code: "NON_MONOTONIC_TIMESTAMP", at: i });
    }
    if (e.type === "STATE_CHECKPOINT") {
      checkpointCount += 1;
      if (typeof e.stateHash !== "string" || !stateHashRe.test(e.stateHash)) {
        violations.push({ code: "INVALID_STATE_HASH", at: i });
      }
    }
    head = computeNextHash(head, e);
  }

  const definedPolicyIds = events
    .map((e) => e.policyId)
    .filter((v): v is string => typeof v === "string");

  const observedPolicyId = definedPolicyIds.length > 0 ? definedPolicyIds[0] : undefined;

  if (definedPolicyIds.length > 1) {
    const first = definedPolicyIds[0];
    for (let i = 1; i < definedPolicyIds.length; i++) {
      if (definedPolicyIds[i] !== first) {
        violations.push({ code: "MIXED_POLICY_ID", detail: `observed multiple policyId values` });
        break;
      }
    }
  }

  if (opts?.policyId && observedPolicyId && opts.policyId !== observedPolicyId) {
    violations.push({
      code: "POLICY_ID_MISMATCH",
      detail: `expected=${opts.policyId}, observed=${observedPolicyId}`
    });
  }

  if (violations.length > 0) {
    return {
      ok: false,
      status: "violation",
      violations,
      expectedPolicyId: opts?.policyId,
      observedPolicyId,
      auditHeadHash: head
    };
  }

  if (mode === "strict" && checkpointCount === 0) {
    return {
      ok: false,
      status: "inconclusive",
      violations: [{ code: "NO_STATE_ANCHOR" }],
      expectedPolicyId: opts?.policyId,
      observedPolicyId,
      auditHeadHash: head
    };
  }

  return {
    ok: true,
    status: "ok",
    violations: [],
    expectedPolicyId: opts?.policyId,
    observedPolicyId,
    auditHeadHash: head
  };
}
