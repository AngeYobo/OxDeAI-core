import { createHash } from "node:crypto";
import { canonicalJson } from "../crypto/hashes.js";
import type { AuditEvent } from "../audit/AuditLog.js";
import type { VerificationResult, VerificationViolation, VerifyAuditOptions } from "./types.js";

function sortViolations(violations: VerificationViolation[]): VerificationViolation[] {
  return [...violations].sort((a, b) => {
    if (a.code < b.code) return -1;
    if (a.code > b.code) return 1;
    return (a.index ?? 0) - (b.index ?? 0);
  });
}

function canonicalizeAuditEvent(event: AuditEvent): Uint8Array {
  const normalized = {
    ...event,
    policyId: event.policyId ?? null
  };
  return new TextEncoder().encode(canonicalJson(normalized));
}

function computeNextHash(prev: string, event: AuditEvent): string {
  const bytes = canonicalizeAuditEvent(event);
  return createHash("sha256")
    .update(prev, "utf8")
    .update("\n", "utf8")
    .update(bytes)
    .digest("hex");
}

function asAuditEvent(value: unknown): value is AuditEvent {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** @public */
export function verifyAuditEvents(
  events: readonly AuditEvent[],
  opts?: VerifyAuditOptions
): VerificationResult {
  if (!Array.isArray(events)) {
    return {
      ok: false,
      status: "invalid",
      violations: sortViolations([{ code: "MALFORMED_EVENT", message: "events must be an array" }])
    };
  }

  const mode = opts?.mode ?? "strict";
  const requireStateAnchors = opts?.requireStateAnchors ?? (mode === "strict");

  const violations: VerificationViolation[] = [];
  const policyIds = new Set<string>();
  let inferredPolicyId: string | undefined;
  let hasStateAnchor = false;
  let head = "";
  let lastTimestamp: number | undefined;

  for (let i = 0; i < events.length; i++) {
    const raw = events[i] as unknown;

    if (!asAuditEvent(raw)) {
      violations.push({ code: "MALFORMED_EVENT", message: "event must be an object", index: i });
      continue;
    }

    const event = raw;

    if (typeof event.timestamp !== "number" || !Number.isFinite(event.timestamp)) {
      violations.push({ code: "MALFORMED_EVENT", message: "event.timestamp must be a finite number", index: i });
      continue;
    }

    if (lastTimestamp !== undefined && event.timestamp < lastTimestamp) {
      violations.push({
        code: "NON_MONOTONIC_TIMESTAMP",
        message: `event timestamps must be non-decreasing (prev=${lastTimestamp}, next=${event.timestamp})`,
        index: i
      });
    }
    lastTimestamp = event.timestamp;

    if (opts?.expectedPolicyId !== undefined) {
      if (typeof event.policyId !== "string" || event.policyId.length === 0) {
        violations.push({
          code: "POLICY_ID_MISSING",
          message: "event.policyId is required when expectedPolicyId is provided",
          index: i
        });
      } else if (event.policyId !== opts.expectedPolicyId) {
        violations.push({
          code: "POLICY_ID_MISMATCH",
          message: `event.policyId mismatch (expected=${opts.expectedPolicyId}, got=${event.policyId})`,
          index: i
        });
      }
    }

    if (typeof event.policyId === "string" && event.policyId.length > 0) {
      policyIds.add(event.policyId);
    }

    if (event.type === "STATE_CHECKPOINT" && typeof event.stateHash === "string") {
      hasStateAnchor = true;
    }

    try {
      head = computeNextHash(head, event);
    } catch {
      violations.push({ code: "HASH_CHAIN_INVALID", message: "failed to recompute hash chain" });
    }
  }

  if (policyIds.size > 1) {
    violations.push({ code: "MIXED_POLICY_ID", message: "multiple distinct policyId values observed" });
  } else if (policyIds.size === 1) {
    inferredPolicyId = [...policyIds][0];
  }

  if (requireStateAnchors && !hasStateAnchor) {
    violations.push({ code: "NO_STATE_ANCHOR", message: "no STATE_CHECKPOINT event with stateHash found" });
  }

  const sorted = sortViolations(violations);
  const hasInvalidViolation = sorted.some((v) => v.code !== "NO_STATE_ANCHOR");
  const hasAnchorViolation = sorted.some((v) => v.code === "NO_STATE_ANCHOR");

  if (hasInvalidViolation) {
    return {
      ok: false,
      status: "invalid",
      policyId: inferredPolicyId,
      auditHeadHash: head,
      violations: sorted
    };
  }

  if (hasAnchorViolation) {
    return {
      ok: false,
      status: "inconclusive",
      policyId: inferredPolicyId,
      auditHeadHash: head,
      violations: sorted
    };
  }

  return {
    ok: true,
    status: "ok",
    policyId: inferredPolicyId,
    auditHeadHash: head,
    violations: []
  };
}
