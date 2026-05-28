// SPDX-License-Identifier: Apache-2.0
import type { KeySet } from "../types/keyset.js";
import type { SignedKRLV1, VerifySignedKrlOptions } from "../types/signed-krl.js";
import type { VerificationResult, VerificationViolation } from "./types.js";
import {
  SIGNING_DOMAINS,
  findKeyInKeySets,
  keyIsActiveAt,
  verifyEd25519,
} from "../crypto/signatures.js";

// ── Helpers ───────────────────────────────────────────────────────────────────

function nowSeconds(now: number | undefined): number {
  return now !== undefined ? now : Math.floor(Date.now() / 1000);
}

function hasText(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function sortViolations(violations: VerificationViolation[]): VerificationViolation[] {
  return [...violations].sort((a, b) => {
    if (a.code < b.code) return -1;
    if (a.code > b.code) return 1;
    return 0;
  });
}

// ── signedKrlSigningPayload ───────────────────────────────────────────────────

/**
 * Produces the canonical signing payload for a `SignedKRLV1` envelope.
 *
 * Includes all normative fields — version, issuer, krl_version, issued_at,
 * not_after, revoked_kids, nonce (when present), signature.alg, signature.kid.
 * Excludes only `signature.sig` so the preimage is reproducible by any
 * implementation without access to the signature bytes themselves.
 *
 * Signing preimage: `signatureInput(SIGNING_DOMAINS.KRL_V1, signedKrlSigningPayload(envelope))`
 *
 * @public
 */
export function signedKrlSigningPayload(
  envelope: SignedKRLV1
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    version:      envelope.version,
    issuer:       envelope.issuer,
    krl_version:  envelope.krl_version,
    issued_at:    envelope.issued_at,
    not_after:    envelope.not_after,
    revoked_kids: envelope.revoked_kids,
    signature: {
      alg: envelope.signature.alg,
      kid: envelope.signature.kid,
    },
  };
  if (envelope.nonce !== undefined) {
    payload.nonce = envelope.nonce;
  }
  return payload;
}

// ── verifySignedKrl ───────────────────────────────────────────────────────────

/**
 * Verify a `SignedKRLV1` artifact.
 *
 * Pure and synchronous. Never throws for verification failure — all results
 * are returned as `VerificationResult`.
 *
 * Verification order:
 *   1. Structural validation — required fields, types, duplicate revoked_kids.
 *      Returns early with all structural violations if any are found.
 *   2. Version regression — `krl_version < previousKrlVersionByIssuer[issuer]`
 *      → `KRL_VERSION_REGRESSION`.
 *   3. Expiry — strict zero-tolerance: `now >= not_after` → `KRL_EXPIRED`.
 *   4. Signing key lookup — not found → `KRL_UNKNOWN_SIGNING_KID`;
 *      found but inactive → `KRL_SIGNING_KEY_INACTIVE`.
 *   5. Signature — `verifyEd25519(KRL_V1, signedKrlSigningPayload(envelope), sig, key)`
 *      → `KRL_SIG_INVALID`.
 *
 * @public
 */
export function verifySignedKrl(
  envelope: unknown,
  opts?: VerifySignedKrlOptions
): VerificationResult {
  const violations: VerificationViolation[] = [];
  const now = nowSeconds(opts?.now);

  // ── Not a plain object ─────────────────────────────────────────────────────
  if (!isRecord(envelope)) {
    return {
      ok: false,
      status: "invalid",
      violations: [{ code: "KRL_MALFORMED", message: "envelope must be a non-null object" }],
    };
  }

  const e = envelope as Record<string, unknown>;

  // ── version ────────────────────────────────────────────────────────────────
  if (e["version"] !== "SignedKRLV1") {
    violations.push({ code: "KRL_MALFORMED", message: 'version must equal "SignedKRLV1"' });
  }

  // ── issuer ─────────────────────────────────────────────────────────────────
  if (!hasText(e["issuer"])) {
    violations.push({ code: "KRL_MALFORMED", message: "issuer must be a non-empty string" });
  }

  // ── krl_version ────────────────────────────────────────────────────────────
  const kv = e["krl_version"];
  if (typeof kv !== "number" || !Number.isSafeInteger(kv) || kv < 0) {
    violations.push({ code: "KRL_MALFORMED", message: "krl_version must be a non-negative safe integer" });
  }

  // ── issued_at ──────────────────────────────────────────────────────────────
  if (typeof e["issued_at"] !== "number" || !Number.isInteger(e["issued_at"])) {
    violations.push({ code: "KRL_MALFORMED", message: "issued_at must be an integer unix timestamp" });
  }

  // ── not_after ─────────────────────────────────────────────────────────────
  if (typeof e["not_after"] !== "number" || !Number.isInteger(e["not_after"])) {
    violations.push({ code: "KRL_MALFORMED", message: "not_after must be an integer unix timestamp" });
  }

  // ── revoked_kids ───────────────────────────────────────────────────────────
  const kids = e["revoked_kids"];
  if (!Array.isArray(kids)) {
    violations.push({ code: "KRL_MALFORMED", message: "revoked_kids must be an array of strings" });
  } else {
    // All entries must be strings
    let hasNonString = false;
    for (const k of kids) {
      if (typeof k !== "string") {
        violations.push({ code: "KRL_MALFORMED", message: "revoked_kids must be an array of strings" });
        hasNonString = true;
        break;
      }
    }
    // Duplicate detection (per-spec: producers MUST deduplicate; verifiers MUST reject duplicates)
    if (!hasNonString) {
      const seen = new Set<string>();
      for (const k of kids as string[]) {
        if (seen.has(k)) {
          violations.push({ code: "KRL_MALFORMED", message: "duplicate entry in revoked_kids" });
          break;
        }
        seen.add(k);
      }
    }
  }

  // ── nonce (optional) ──────────────────────────────────────────────────────
  if (e["nonce"] !== undefined && typeof e["nonce"] !== "string") {
    violations.push({ code: "KRL_MALFORMED", message: "nonce must be a string when present" });
  }

  // ── signature object ───────────────────────────────────────────────────────
  const sig = e["signature"];
  if (!isRecord(sig)) {
    violations.push({ code: "KRL_MALFORMED", message: "signature must be a non-null object" });
    // Cannot proceed with signature field checks — return now
    return { ok: false, status: "invalid", violations: sortViolations(violations) };
  }

  const sigObj = sig as Record<string, unknown>;

  // ── signature.alg ──────────────────────────────────────────────────────────
  if (sigObj["alg"] !== "Ed25519") {
    if (hasText(sigObj["alg"])) {
      violations.push({ code: "KRL_UNSUPPORTED_ALG", message: "only Ed25519 is supported for SignedKRLV1 signing" });
    } else {
      violations.push({ code: "KRL_MALFORMED", message: "signature.alg must be a non-empty string" });
    }
  }

  // ── signature.kid ──────────────────────────────────────────────────────────
  if (!hasText(sigObj["kid"])) {
    violations.push({ code: "KRL_MALFORMED", message: "signature.kid must be a non-empty string" });
  }

  // ── signature.sig ──────────────────────────────────────────────────────────
  if (!hasText(sigObj["sig"])) {
    violations.push({ code: "KRL_MALFORMED", message: "signature.sig must be a non-empty string" });
  }

  // Return early if any structural violations were found — do not attempt
  // semantic or cryptographic checks on a malformed envelope.
  if (violations.length > 0) {
    return { ok: false, status: "invalid", violations: sortViolations(violations) };
  }

  // ── Structurally valid — safe cast to SignedKRLV1 ─────────────────────────
  const krl = envelope as SignedKRLV1;

  // ── Version regression ─────────────────────────────────────────────────────
  if (opts?.previousKrlVersionByIssuer !== undefined) {
    const prev = opts.previousKrlVersionByIssuer[krl.issuer];
    if (prev !== undefined && krl.krl_version < prev) {
      violations.push({
        code: "KRL_VERSION_REGRESSION",
        message: `krl_version ${krl.krl_version} is less than the previously accepted version ${prev} for issuer "${krl.issuer}"`,
      });
    }
  }

  // ── Expiry (strict zero-tolerance: valid iff now < not_after) ────────────
  if (now >= krl.not_after) {
    violations.push({ code: "KRL_EXPIRED", message: "KRL has expired" });
  }

  // ── Signature verification ─────────────────────────────────────────────────
  const trustedRaw = opts?.trustedKeySets;
  const trusted: KeySet[] = trustedRaw
    ? (Array.isArray(trustedRaw) ? trustedRaw as KeySet[] : [trustedRaw as KeySet])
    : [];

  if (trusted.length === 0) {
    violations.push({
      code: "KRL_UNKNOWN_SIGNING_KID",
      message: "no trusted KRL signing key sets provided",
    });
  } else {
    const key = findKeyInKeySets(trusted, krl.issuer, krl.signature.kid, "Ed25519");
    if (!key) {
      violations.push({
        code: "KRL_UNKNOWN_SIGNING_KID",
        message: "KRL signing kid not found in trusted key sets",
      });
    } else if (!keyIsActiveAt(key, now)) {
      violations.push({
        code: "KRL_SIGNING_KEY_INACTIVE",
        message: "KRL signing key is not active at verification time",
      });
    } else {
      const payload = signedKrlSigningPayload(krl);
      if (!verifyEd25519(SIGNING_DOMAINS.KRL_V1, payload, krl.signature.sig, key.public_key)) {
        violations.push({ code: "KRL_SIG_INVALID", message: "Ed25519 signature verification failed" });
      }
    }
  }

  if (violations.length > 0) {
    return { ok: false, status: "invalid", violations: sortViolations(violations) };
  }

  return { ok: true, status: "ok", violations: [] };
}
