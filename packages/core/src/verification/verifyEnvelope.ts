import { decodeEnvelope } from "./envelope.js";
import { verifySnapshot } from "./verifySnapshot.js";
import { verifyAuditEvents } from "./verifyAuditEvents.js";
import type { VerificationResult, VerificationViolation, VerifyEnvelopeOptions } from "./types.js";

function sortViolations(violations: VerificationViolation[]): VerificationViolation[] {
  return [...violations].sort((a, b) => {
    if (a.code < b.code) return -1;
    if (a.code > b.code) return 1;
    return (a.index ?? 0) - (b.index ?? 0);
  });
}

/** @public */
export function verifyEnvelope(
  envelopeBytes: Uint8Array,
  opts?: VerifyEnvelopeOptions
): VerificationResult {
  let envelope;
  try {
    envelope = decodeEnvelope(envelopeBytes);
  } catch {
    return {
      ok: false,
      status: "invalid",
      violations: [{ code: "ENVELOPE_MALFORMED", message: "envelope decode failed" }]
    };
  }

  const snapshotResult = verifySnapshot(envelope.snapshot, {
    expectedPolicyId: opts?.expectedPolicyId
  });

  const auditResult = verifyAuditEvents(envelope.events, {
    expectedPolicyId: opts?.expectedPolicyId,
    mode: opts?.mode
  });

  const violations: VerificationViolation[] = [...snapshotResult.violations, ...auditResult.violations];

  const snapshotPolicyId = snapshotResult.policyId;
  const auditPolicyId = auditResult.policyId;

  if (!snapshotPolicyId || !auditPolicyId) {
    violations.push({ code: "POLICY_ID_MISSING", message: "snapshot and audit must both include policyId" });
  } else if (snapshotPolicyId !== auditPolicyId) {
    violations.push({ code: "POLICY_ID_MISMATCH", message: "snapshot policyId does not match audit policyId" });
  }

  const sorted = sortViolations(violations);
  const hasInvalid =
    snapshotResult.status === "invalid" ||
    auditResult.status === "invalid" ||
    sorted.some((v) => v.code !== "NO_STATE_ANCHOR");

  if (hasInvalid) {
    return {
      ok: false,
      status: "invalid",
      violations: sorted,
      policyId: snapshotPolicyId ?? auditPolicyId,
      stateHash: snapshotResult.stateHash,
      auditHeadHash: auditResult.auditHeadHash
    };
  }

  if (snapshotResult.status === "inconclusive" || auditResult.status === "inconclusive") {
    return {
      ok: false,
      status: "inconclusive",
      violations: sorted,
      policyId: snapshotPolicyId ?? auditPolicyId,
      stateHash: snapshotResult.stateHash,
      auditHeadHash: auditResult.auditHeadHash
    };
  }

  return {
    ok: true,
    status: "ok",
    violations: [],
    policyId: snapshotPolicyId,
    stateHash: snapshotResult.stateHash,
    auditHeadHash: auditResult.auditHeadHash
  };
}
