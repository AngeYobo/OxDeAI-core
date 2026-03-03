import { sha256HexFromJson } from "../crypto/hashes.js";
import { decodeCanonicalState } from "../snapshot/CanonicalCodec.js";
import type { SnapshotVerificationResult } from "./types.js";

function invalid(
  code: string,
  extra?: Partial<Pick<SnapshotVerificationResult, "policyId" | "formatVersion">>
): SnapshotVerificationResult {
  return {
    status: "invalid",
    violations: [code],
    policyId: extra?.policyId,
    formatVersion: extra?.formatVersion
  };
}

export function verifySnapshot(
  snapshotBytes: Uint8Array,
  opts?: { expectedPolicyId?: string }
): SnapshotVerificationResult {
  let snapshot: ReturnType<typeof decodeCanonicalState>;

  try {
    snapshot = decodeCanonicalState(snapshotBytes);
  } catch {
    try {
      const parsed = JSON.parse(new TextDecoder().decode(snapshotBytes)) as unknown;
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        const obj = parsed as Record<string, unknown>;

        if (obj.formatVersion !== 1) {
          return invalid("SNAPSHOT_UNSUPPORTED_VERSION", {
            formatVersion: typeof obj.formatVersion === "number" ? obj.formatVersion : undefined,
            policyId: typeof obj.policyId === "string" ? obj.policyId : undefined
          });
        }

        if (!("modules" in obj) || typeof obj.modules !== "object" || obj.modules === null || Array.isArray(obj.modules)) {
          return invalid("SNAPSHOT_MALFORMED_MODULES", {
            policyId: typeof obj.policyId === "string" ? obj.policyId : undefined,
            formatVersion: 1
          });
        }

        if (typeof obj.policyId !== "string" || obj.policyId.length === 0) {
          return invalid("SNAPSHOT_MISSING_POLICY_ID", { formatVersion: 1 });
        }
      }
    } catch {
      // Keep decode error as authoritative when payload cannot be interpreted.
    }

    return invalid("SNAPSHOT_DECODE_FAILED");
  }

  if (snapshot.formatVersion !== 1) {
    return invalid("SNAPSHOT_UNSUPPORTED_VERSION", {
      policyId: snapshot.policyId,
      formatVersion: snapshot.formatVersion
    });
  }

  if (typeof snapshot.policyId !== "string" || snapshot.policyId.length === 0) {
    return invalid("SNAPSHOT_MISSING_POLICY_ID", { formatVersion: 1 });
  }

  if (opts?.expectedPolicyId && opts.expectedPolicyId !== snapshot.policyId) {
    return invalid("SNAPSHOT_POLICY_ID_MISMATCH", {
      policyId: snapshot.policyId,
      formatVersion: 1
    });
  }

  if (!snapshot.modules || typeof snapshot.modules !== "object" || Array.isArray(snapshot.modules)) {
    return invalid("SNAPSHOT_MALFORMED_MODULES", {
      policyId: snapshot.policyId,
      formatVersion: 1
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
      status: "ok",
      violations: [],
      stateHash,
      policyId: snapshot.policyId,
      formatVersion: 1
    };
  } catch {
    return invalid("SNAPSHOT_MALFORMED_MODULES", {
      policyId: snapshot.policyId,
      formatVersion: 1
    });
  }
}
