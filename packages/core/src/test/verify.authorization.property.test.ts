// SPDX-License-Identifier: Apache-2.0
/**
 * verify.authorization.property.test.ts
 *
 * Property-based analogue of delegation.property.test.ts's D-P5 ("mutating
 * any signed field is always detected"), applied to AuthorizationV1 itself.
 *
 * The authoritative bound-field set is derived from
 * `authorizationSigningPayload()` (verifyAuthorization.ts) for the flat
 * (non-nested-signature) wire form produced by `signAuthorizationEd25519`:
 * every field it copies into the signing payload is a bound field, and
 * mutating any one of them after signing must change the canonical payload
 * bytes and therefore invalidate the Ed25519 signature.
 *
 * That is: auth_id, issuer, audience, intent_hash, state_hash, policy_id,
 * decision, issued_at, expiry, alg, kid, plus the optional version/nonce/
 * capability fields (populated here specifically so mutating them changes an
 * already-present value rather than merely making an absent field present).
 *
 * Each mutation is applied to the ALREADY-SIGNED artifact — never by
 * constructing a new object and re-signing it — so the test exercises actual
 * signature-binding, not merely "a differently-built object is invalid."
 *
 * `expectedIssuer` / `expectedAudience` / `expectedPolicyId` are deliberately
 * NOT passed to `verifyAuthorization` in this file, so a caught mutation can
 * only be attributed to the cryptographic signature binding (or an intrinsic
 * structural check such as `decision`/`alg`/`kid`), not to an independent
 * caller-supplied expected-value equality check.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { signAuthorizationEd25519, verifyAuthorization } from "../verification/verifyAuthorization.js";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { KeySet } from "../types/keyset.js";

// ── PRNG (same seeded convention as delegation.property.test.ts) ────────────

const DEFAULT_CASES = Number(process.env.PBT_CASES ?? "100");
const BASE_SEED = Number(process.env.PBT_SEED ?? "20260401");
const ONLY_SEED = process.env.PBT_ONLY_SEED ? Number(process.env.PBT_ONLY_SEED) : undefined;

function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng: () => number, min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function pick<T>(rng: () => number, values: readonly T[]): T {
  return values[randInt(rng, 0, values.length - 1)]!;
}

function seeds(): number[] {
  if (ONLY_SEED !== undefined) return [ONLY_SEED];
  const out: number[] = [];
  for (let i = 0; i < DEFAULT_CASES; i++) out.push(BASE_SEED + i);
  return out;
}

function flipHexChar(v: string): string {
  return (v[0] === "a" ? "b" : "a") + v.slice(1);
}

// ── Fixed key material and timestamps ────────────────────────────────────────

const KEYS = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const KEYSET: KeySet = {
  issuer: "issuer-AP",
  version: "1",
  keys: [{ kid: "kid-ap-1", alg: "Ed25519", public_key: KEYS.publicKey }],
};

const T_ISSUED = 1_000_000;
const T_NOW = 1_001_000;
const T_EXPIRY = 1_003_600;

function makeSignedAuth(): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      version: "AuthorizationV1",
      auth_id: "f".repeat(64),
      issuer: "issuer-AP",
      audience: "rp-AP",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "c".repeat(64),
      decision: "ALLOW",
      issued_at: T_ISSUED,
      expiry: T_EXPIRY,
      kid: "kid-ap-1",
      nonce: "nonce-baseline",
      capability: "capability-baseline",
    },
    KEYS.privateKey,
  );
}

type NamedMutation = { target: string; apply: (auth: AuthorizationV1) => AuthorizationV1 };

// Every field `authorizationSigningPayload()` copies into the flat-form
// signing payload — the complete bound-field set for this wire form.
const MUTATIONS: NamedMutation[] = [
  { target: "auth_id", apply: (a) => ({ ...a, auth_id: flipHexChar(a.auth_id) }) },
  { target: "issuer", apply: (a) => ({ ...a, issuer: a.issuer + "-evil" }) },
  { target: "audience", apply: (a) => ({ ...a, audience: a.audience + "-evil" }) },
  { target: "intent_hash", apply: (a) => ({ ...a, intent_hash: flipHexChar(a.intent_hash) }) },
  { target: "state_hash", apply: (a) => ({ ...a, state_hash: flipHexChar(a.state_hash) }) },
  { target: "policy_id", apply: (a) => ({ ...a, policy_id: flipHexChar(a.policy_id) }) },
  { target: "decision", apply: (a) => ({ ...a, decision: "DENY" }) },
  { target: "issued_at", apply: (a) => ({ ...a, issued_at: a.issued_at + 1 }) },
  { target: "expiry", apply: (a) => ({ ...a, expiry: a.expiry - 1 }) },
  { target: "alg", apply: (a) => ({ ...a, alg: "HMAC-SHA256" }) },
  { target: "kid", apply: (a) => ({ ...a, kid: a.kid + "-evil" }) },
  {
    target: "version",
    apply: (a) => ({ ...a, version: "AuthorizationV1-evil" as unknown as AuthorizationV1["version"] }),
  },
  { target: "nonce", apply: (a) => ({ ...a, nonce: (a.nonce ?? "") + "-evil" }) },
  { target: "capability", apply: (a) => ({ ...a, capability: (a.capability ?? "") + "-evil" }) },
];

// Full AUTH_* violation-code union (verification/types.ts). Used only to
// document that a caught mutation is attributable to a recognized
// verification check, mirroring D-P5's TAMPER_CODES.
const TAMPER_CODES = new Set([
  "AUTH_DECISION_INVALID",
  "AUTH_EXPIRED",
  "AUTH_ISSUED_AT_IMPLAUSIBLE",
  "AUTH_MISSING_FIELD",
  "AUTH_ISSUER_MISMATCH",
  "AUTH_AUDIENCE_MISMATCH",
  "AUTH_POLICY_ID_MISMATCH",
  "AUTH_REPLAY",
  "AUTH_ALG_UNSUPPORTED",
  "AUTH_KID_UNKNOWN",
  "AUTH_SIGNATURE_INVALID",
  "AUTH_TRUST_MISSING",
  "AUTH_KEY_INACTIVE",
]);

test("property: a validly-signed AuthorizationV1 with any one bound field mutated after signing must fail verification", () => {
  const base = makeSignedAuth();

  // Control: the unmutated artifact must verify ok. Otherwise a failure below
  // would be indistinguishable from a broken fixture.
  const control = verifyAuthorization(base, {
    now: T_NOW,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });
  assert.equal(control.status, "ok", `control fixture must verify ok, got ${JSON.stringify(control.violations)}`);
  assert.equal(control.signatureVerified, true);

  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const mutation = pick(rng, MUTATIONS);
    const tampered = mutation.apply(base);

    const out = verifyAuthorization(tampered, {
      now: T_NOW,
      trustedKeySets: KEYSET,
      requireSignatureVerification: true,
    });

    assert.equal(
      out.ok,
      false,
      `seed=${seed} target=${mutation.target}: mutated authorization must not verify ok`,
    );
    assert.equal(out.status, "invalid", `seed=${seed} target=${mutation.target}`);
    assert.ok(
      out.violations.length > 0 && out.violations.every((v) => TAMPER_CODES.has(v.code)),
      `seed=${seed} target=${mutation.target}: expected only recognized AUTH_* violations, ` +
        `got ${JSON.stringify(out.violations)}`,
    );
  }
});

test("control: mutating a field NOT covered by the signature (audience under best-effort, no expectedAudience) still fails via signature binding", () => {
  // Deterministic companion to the property above, explicitly for the field
  // the task calls out by name: audience. Without expectedAudience supplied,
  // the ONLY thing that can catch this mutation is the signature — proving
  // audience is bound by the signature itself, not merely checked by policy.
  const base = makeSignedAuth();
  const tampered: AuthorizationV1 = { ...base, audience: "attacker-audience" };

  const out = verifyAuthorization(tampered, {
    now: T_NOW,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });

  assert.equal(out.ok, false);
  assert.ok(out.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
});
