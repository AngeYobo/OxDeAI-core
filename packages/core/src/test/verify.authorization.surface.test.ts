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
  // Configured posture is permissive (best-effort default); the *absence* of a
  // signature check is conveyed by signatureVerified/coverage, not the mode.
  assert.equal(out.signatureVerified, false);
  assert.equal(out.verificationMode, "permissive");
  assert.equal(out.verificationCoverage, "none");
});

test("forged signature not reported as verified, but coverage reflects the surface that was checked", () => {
  // Tamper a signed field so the Ed25519 signature no longer matches, then
  // verify in best-effort mode WITH a trusted key set (so a crypto check runs).
  // The check DID execute against the full AuthorizationV1 payload, so coverage
  // is "authorization-v1-full" even though authentication failed — the failure
  // is conveyed by signatureVerified, keeping the two descriptors orthogonal.
  const forged = { ...makeAuth(), state_hash: "d".repeat(64) };
  const out = verifyAuthorization(forged, { now: 1010, trustedKeySets: KEYSET });
  assert.equal(out.ok, false);
  assert.equal(out.signatureVerified, false);
  assert.equal(out.verificationMode, "permissive");
  assert.equal(out.verificationCoverage, "authorization-v1-full");
  assert.ok(out.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
});

test("forged signature rejected in strict mode: not verified, full coverage (a check ran)", () => {
  const forged = { ...makeAuth(), audience: "rp-EVIL" };
  const out = verifyAuthorization(forged, { now: 1010, mode: "strict", trustedKeySets: KEYSET });
  assert.equal(out.ok, false);
  assert.equal(out.signatureVerified, false);
  assert.equal(out.verificationMode, "strict");
  assert.equal(out.verificationCoverage, "authorization-v1-full");
  assert.ok(out.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
});

test("permissive-without-crypto is distinguishable from strict verification", () => {
  const structural = verifyAuthorization(makeAuth(), { now: 1010 });
  const strict = verifyAuthorization(makeAuth(), { now: 1010, mode: "strict", trustedKeySets: KEYSET });
  // Distinguished by posture (mode) AND by whether a signature was checked.
  assert.notEqual(structural.verificationMode, strict.verificationMode);
  assert.equal(structural.verificationMode, "permissive");
  assert.equal(strict.verificationMode, "strict");
  assert.equal(structural.signatureVerified, false);
  assert.equal(structural.verificationCoverage, "none");
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
  // Trust could not be resolved so no signature was checked; the posture is
  // still the configured "permissive" — the missing check shows in
  // signatureVerified/coverage, not the mode.
  assert.equal(out.verificationMode, "permissive");
  assert.equal(out.verificationCoverage, "none");
  assert.ok(out.violations.some((v) => v.code === "AUTH_KID_UNKNOWN"));
});

test("strict + ok invariant: a passing strict verification always ran and passed full cryptographic coverage", () => {
  const out = verifyAuthorization(makeAuth(), { now: 1010, mode: "strict", trustedKeySets: KEYSET });
  assert.equal(out.verificationMode, "strict");
  assert.equal(out.ok, true);
  // The invariant: verificationMode === "strict" && ok === true ALWAYS implies
  // signatureVerified === true && verificationCoverage === "authorization-v1-full".
  assert.equal(out.signatureVerified, true);
  assert.equal(out.verificationCoverage, "authorization-v1-full");
});

test("strict mode cannot pass an HMAC authorization without a shared secret (no silent crypto bypass)", () => {
  // mode:strict + non-empty trustedKeySets + HMAC-SHA256 alg + no legacyHmacSecret
  // must NOT yield ok:true. Strict now implies signature verification is required,
  // so the missing HMAC secret surfaces as AUTH_TRUST_MISSING rather than an
  // unauthenticated ALLOW. This is the precise gap the requireSig fix closes.
  const hmacAuth = { ...makeAuth(), alg: "HMAC-SHA256" as const };
  const out = verifyAuthorization(hmacAuth, { now: 1010, mode: "strict", trustedKeySets: KEYSET });
  assert.equal(out.ok, false);
  assert.equal(out.signatureVerified, false);
  assert.equal(out.verificationMode, "strict");
  // No cryptographic verifier ran (no secret to check against), so coverage is "none".
  assert.equal(out.verificationCoverage, "none");
  assert.ok(out.violations.some((v) => v.code === "AUTH_TRUST_MISSING"));
});
