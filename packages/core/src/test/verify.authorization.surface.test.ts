// SPDX-License-Identifier: Apache-2.0
/**
 * verify.authorization.surface.test.ts
 *
 * Verification-surface descriptors (#172): a verification result must make it
 * impossible to mistake a merely-structural check for a cryptographically
 * verified authorization. These tests pin the contract that
 * `signatureVerified` is true ONLY when a cryptographic check actually ran and
 * succeeded, and that `verificationMode` / `verificationCoverage` describe the
 * posture and covered surface honestly.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { signAuthorizationEd25519, verifyAuthorization } from "../verification/index.js";
import type { KeySet } from "../types/keyset.js";

const KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const KEYSET: KeySet = {
  issuer: "issuer-A",
  version: "1",
  keys: [{ kid: "2026-01", alg: "Ed25519", public_key: KEYPAIR.publicKey }],
};

function makeAuth(overrides?: { issued_at?: number; expiry?: number }) {
  return signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: "issuer-A",
      audience: "rp-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "c".repeat(64),
      decision: "ALLOW",
      issued_at: overrides?.issued_at ?? 1000,
      expiry: overrides?.expiry ?? 1060,
      kid: "2026-01",
    },
    KEYPAIR.privateKey
  );
}

test("signatureVerified === true only when cryptographic verification actually ran and succeeded", () => {
  const out = verifyAuthorization(makeAuth(), {
    now: 1010,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });
  assert.equal(out.ok, true);
  assert.equal(out.signatureVerified, true);
  assert.equal(out.verificationMode, "permissive");
  assert.equal(out.verificationCoverage, "authorization-v1-full");
});

test("strict mode with trustedKeySets reports strict posture and full coverage", () => {
  const out = verifyAuthorization(makeAuth(), {
    now: 1010,
    mode: "strict",
    trustedKeySets: KEYSET,
  });
  assert.equal(out.ok, true);
  assert.equal(out.signatureVerified, true);
  assert.equal(out.verificationMode, "strict");
  assert.equal(out.verificationCoverage, "authorization-v1-full");
});

test("missing trusted key set does not silently produce a fully verified result", () => {
  // Structurally valid, non-expired, but no trustedKeySets: the result is
  // `ok: true` for backward compatibility, yet must NOT claim signature
  // verification occurred.
  const out = verifyAuthorization(makeAuth(), { now: 1010 });
  assert.equal(out.ok, true);
  assert.equal(out.signatureVerified, false);
  assert.equal(out.verificationMode, "structure-only");
  assert.equal(out.verificationCoverage, "none");
});

test("forged signature not reported as fully verified in default/permissive mode", () => {
  // Tamper a signed field so the Ed25519 signature no longer matches, then
  // verify in best-effort mode WITH a trusted key set (so a crypto check runs).
  const forged = { ...makeAuth(), state_hash: "d".repeat(64) };
  const out = verifyAuthorization(forged, { now: 1010, trustedKeySets: KEYSET });
  assert.equal(out.ok, false);
  assert.equal(out.signatureVerified, false);
  assert.equal(out.verificationMode, "permissive");
  assert.equal(out.verificationCoverage, "none");
  assert.ok(out.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
});

test("forged signature rejected in strict mode and not marked verified", () => {
  const forged = { ...makeAuth(), audience: "rp-EVIL" };
  const out = verifyAuthorization(forged, { now: 1010, mode: "strict", trustedKeySets: KEYSET });
  assert.equal(out.ok, false);
  assert.equal(out.signatureVerified, false);
  assert.equal(out.verificationMode, "strict");
  assert.equal(out.verificationCoverage, "none");
  assert.ok(out.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
});

test("explicit non-crypto (structure-only) result is distinguishable from strict verification", () => {
  const structural = verifyAuthorization(makeAuth(), { now: 1010 });
  const strict = verifyAuthorization(makeAuth(), { now: 1010, mode: "strict", trustedKeySets: KEYSET });
  assert.notEqual(structural.verificationMode, strict.verificationMode);
  assert.equal(structural.verificationMode, "structure-only");
  assert.equal(strict.verificationMode, "strict");
  assert.equal(structural.signatureVerified, false);
  assert.equal(strict.signatureVerified, true);
});

test("signatureVerified is orthogonal to ok: validly-signed but expired is verified yet not ok", () => {
  const out = verifyAuthorization(makeAuth({ issued_at: 1000, expiry: 1060 }), {
    now: 2000, // past expiry
    trustedKeySets: KEYSET,
  });
  assert.equal(out.ok, false);
  assert.equal(out.signatureVerified, true);
  assert.equal(out.verificationCoverage, "authorization-v1-full");
  assert.ok(out.violations.some((v) => v.code === "AUTH_EXPIRED"));
});

test("strict mode without trustedKeySets reports strict posture, no signature verified", () => {
  const out = verifyAuthorization(makeAuth(), { now: 1010, mode: "strict" });
  assert.equal(out.ok, false);
  assert.equal(out.signatureVerified, false);
  assert.equal(out.verificationMode, "strict");
  assert.equal(out.verificationCoverage, "none");
  assert.ok(out.violations.some((v) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
});

test("unknown kid engages no cryptographic check and is not marked verified", () => {
  const out = verifyAuthorization({ ...makeAuth(), kid: "missing" }, {
    now: 1010,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });
  assert.equal(out.ok, false);
  assert.equal(out.signatureVerified, false);
  // No verify function ran (trust could not be resolved), so posture is
  // structure-only rather than permissive.
  assert.equal(out.verificationMode, "structure-only");
  assert.equal(out.verificationCoverage, "none");
  assert.ok(out.violations.some((v) => v.code === "AUTH_KID_UNKNOWN"));
});
