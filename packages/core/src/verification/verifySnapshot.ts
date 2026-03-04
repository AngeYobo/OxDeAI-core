import { sha256HexFromJson } from "../crypto/hashes.js";
import { decodeCanonicalState } from "../snapshot/CanonicalCodec.js";
import type { VerificationResult, VerificationViolation } from "./types.js";

function sortViolations(violations: VerificationViolation[]): VerificationViolation[] {
  return [...violations].sort((a, b) => {
    if (a.code < b.code) return -1;
    if (a.code > b.code) return 1;
    return (a.index ?? 0) - (b.index ?? 0);
  });
}

function invalid(
  message: string,
  extra?: Partial<Pick<VerificationResult, "policyId">>
): VerificationResult {
  return {
    ok: false,
    status: "invalid",
    violations: sortViolations([{ code: "SNAPSHOT_CORRUPT", message }]),
    policyId: extra?.policyId
  };
}

/** @public */
export function verifySnapshot(
  snapshotBytes: Uint8Array,
  opts?: { expectedPolicyId?: string }
): VerificationResult {
  let snapshot: ReturnType<typeof decodeCanonicalState>;

  try {
    snapshot = decodeCanonicalState(snapshotBytes);
  } catch {
    return invalid("snapshot decode failed");
  }

  if (snapshot.formatVersion !== 1) {
    return invalid("unsupported snapshot formatVersion", {
      policyId: snapshot.policyId
    });
  }

  if (typeof snapshot.policyId !== "string" || snapshot.policyId.length === 0) {
    return {
      ok: false,
      status: "invalid",
      violations: sortViolations([{ code: "POLICY_ID_MISSING", message: "snapshot policyId is required" }])
    };
  }

  if (opts?.expectedPolicyId && opts.expectedPolicyId !== snapshot.policyId) {
    return {
      ok: false,
      status: "invalid",
      violations: sortViolations([
        {
          code: "POLICY_ID_MISMATCH",
          message: `snapshot policyId does not match expected policyId`
        }
      ]),
      policyId: snapshot.policyId
    };
  }

  if (!snapshot.modules || typeof snapshot.modules !== "object" || Array.isArray(snapshot.modules)) {
    return invalid("snapshot modules must be an object", {
      policyId: snapshot.policyId
    });
  }

  try {
    const moduleHashes: Record<string, string> = {};
    const ids = Object.keys(snapshot.modules).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    for (const id of ids) {
      moduleHashes[id] = sha256HexFromJson(snapshot.modules[id]);
    }

    const stateHash = sha256HexFromJson({
      formatVersion: 1,
      engineVersion: snapshot.engineVersion,
      policyId: snapshot.policyId,
      modules: moduleHashes
    });

    return {
      ok: true,
      status: "ok",
      violations: [],
      stateHash,
      policyId: snapshot.policyId
    };
  } catch {
    return invalid("snapshot modules are malformed", {
      policyId: snapshot.policyId
    });
  }
}
