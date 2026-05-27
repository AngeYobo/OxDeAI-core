// SPDX-License-Identifier: Apache-2.0
/**
 * Public AuthorizationV1 artifact boundary tests.
 *
 * Acceptance criteria (P0 hardening):
 *   1. toPublicAuthorizationV1 strips legacy/internal engine fields.
 *   2. authorizationSigningPayload excludes legacy fields from Encoding B.
 *   3. delegationParentHash does NOT change when legacy engine fields are present.
 *   4. DelegationV1 parent hash verification does not depend on TypeScript-specific
 *      legacy fields — an independent implementation reproducing only normative
 *      AuthorizationV1 fields arrives at the same parent hash.
 *
 * These tests prove the public protocol surface is stable: any conforming
 * implementation that knows only the normative AuthorizationV1 shape can
 * reproduce all public hashes without access to internal engine state.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import {
  toPublicAuthorizationV1,
  authorizationSigningPayload,
  delegationParentHash,
  signAuthorizationEd25519,
  canonicalJson,
} from "@oxdeai/core";
import type { Authorization, AuthorizationV1 } from "@oxdeai/core";

// ─── Test fixtures ─────────────────────────────────────────────────────────────

const RUNTIME_KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

/** A clean, normative AuthorizationV1 (no legacy fields). */
function makeCleanAuth(): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: "a".repeat(64),
      issuer: "issuer-A",
      audience: "rp-A",
      intent_hash: "b".repeat(64),
      state_hash: "c".repeat(64),
      policy_id: "d".repeat(64),
      decision: "ALLOW",
      issued_at: 1_000_000,
      expiry: 1_000_060,
      kid: "k1",
    },
    RUNTIME_KEYPAIR.privateKey
  );
}

/**
 * Attach legacy/internal engine fields to an existing AuthorizationV1.
 * This simulates what PolicyEngine.evaluatePure() returns at runtime:
 * the Authorization type that carries internal fields alongside the public ones.
 */
function attachLegacyFields(auth: AuthorizationV1): Authorization {
  return {
    ...auth,
    // Legacy aliases — same values as the public fields but different names
    authorization_id: auth.auth_id,
    expires_at: auth.expiry,
    // Engine-internal fields — never part of the public protocol
    engine_signature: "hmac-sig-would-go-here",
    state_snapshot_hash: "e".repeat(64),
    policy_version: "0.1.0",
  } as Authorization;
}

// ─── 1. toPublicAuthorizationV1 strips legacy fields ──────────────────────────

test("toPublicAuthorizationV1: strips legacy engine fields", () => {
  const clean = makeCleanAuth();
  const withLegacy = attachLegacyFields(clean);

  const pub = toPublicAuthorizationV1(withLegacy as unknown as AuthorizationV1);
  const pubRecord = pub as Record<string, unknown>;

  // Legacy fields must not appear in the public artifact
  assert.equal(pubRecord["authorization_id"], undefined, "authorization_id must be stripped");
  assert.equal(pubRecord["engine_signature"], undefined, "engine_signature must be stripped");
  assert.equal(pubRecord["state_snapshot_hash"], undefined, "state_snapshot_hash must be stripped");
  assert.equal(pubRecord["policy_version"], undefined, "policy_version must be stripped");
  assert.equal(pubRecord["expires_at"], undefined, "expires_at alias must be stripped");

  // Normative fields must be preserved
  assert.equal(pub.auth_id, clean.auth_id);
  assert.equal(pub.issuer, clean.issuer);
  assert.equal(pub.audience, clean.audience);
  assert.equal(pub.decision, clean.decision);
  assert.equal(pub.intent_hash, clean.intent_hash);
  assert.equal(pub.state_hash, clean.state_hash);
  assert.equal(pub.policy_id, clean.policy_id);
  assert.equal(pub.issued_at, clean.issued_at);
  assert.equal(pub.expiry, clean.expiry);
  assert.equal(pub.alg, clean.alg);
  assert.equal(pub.kid, clean.kid);
  assert.deepEqual(pub.signature, clean.signature);
});

// ─── 2. toPublicAuthorizationV1 is idempotent ─────────────────────────────────

test("toPublicAuthorizationV1: calling it twice produces the same object shape", () => {
  const clean = makeCleanAuth();
  const pub1 = toPublicAuthorizationV1(clean);
  const pub2 = toPublicAuthorizationV1(pub1);

  assert.equal(
    canonicalJson(pub1 as unknown as Record<string, unknown>),
    canonicalJson(pub2 as unknown as Record<string, unknown>),
    "toPublicAuthorizationV1 must be idempotent"
  );
});

// ─── 3. Legacy fields do NOT change the public canonical hash ─────────────────

test("adding legacy fields does NOT change the toPublicAuthorizationV1 canonical hash", () => {
  const clean = makeCleanAuth();
  const withLegacy = attachLegacyFields(clean);

  const hashClean = canonicalJson(
    toPublicAuthorizationV1(clean) as unknown as Record<string, unknown>
  );
  const hashWithLegacy = canonicalJson(
    toPublicAuthorizationV1(withLegacy as unknown as AuthorizationV1) as unknown as Record<string, unknown>
  );

  assert.equal(
    hashClean,
    hashWithLegacy,
    "canonical hash of toPublicAuthorizationV1 must not change when legacy fields are present"
  );
});

// ─── 4. Encoding B signing payload excludes legacy fields ─────────────────────

test("authorizationSigningPayload (Encoding A): excludes legacy fields", () => {
  const clean = makeCleanAuth();
  const withLegacy = attachLegacyFields(clean);

  const payloadClean = authorizationSigningPayload(clean);
  const payloadWithLegacy = authorizationSigningPayload(withLegacy as unknown as AuthorizationV1);

  const recordClean = payloadClean as Record<string, unknown>;
  const recordWithLegacy = payloadWithLegacy as Record<string, unknown>;

  // Legacy fields must never appear in the signing payload
  assert.equal(recordClean["authorization_id"], undefined, "authorization_id must not be in signing payload");
  assert.equal(recordClean["engine_signature"], undefined, "engine_signature must not be in signing payload");
  assert.equal(recordClean["state_snapshot_hash"], undefined, "state_snapshot_hash must not be in signing payload");
  assert.equal(recordClean["policy_version"], undefined, "policy_version must not be in signing payload");

  assert.equal(recordWithLegacy["authorization_id"], undefined, "authorization_id must not be in signing payload with legacy fields");
  assert.equal(recordWithLegacy["engine_signature"], undefined, "engine_signature must not be in signing payload with legacy fields");
  assert.equal(recordWithLegacy["state_snapshot_hash"], undefined, "state_snapshot_hash must not be in signing payload with legacy fields");
  assert.equal(recordWithLegacy["policy_version"], undefined, "policy_version must not be in signing payload with legacy fields");

  // The signing payload must be identical whether or not legacy fields are present
  assert.equal(
    canonicalJson(payloadClean as Record<string, unknown>),
    canonicalJson(payloadWithLegacy as Record<string, unknown>),
    "signing payload canonical JSON must be identical with or without legacy fields"
  );
});

// ─── 5. delegationParentHash: legacy fields do NOT change the hash ─────────────

test("delegationParentHash: adding legacy fields does NOT change the parent hash", () => {
  const clean = makeCleanAuth();
  const withLegacy = attachLegacyFields(clean);

  const hashClean   = delegationParentHash(clean);
  const hashLegacy  = delegationParentHash(withLegacy as unknown as AuthorizationV1);

  assert.equal(
    hashClean,
    hashLegacy,
    "delegationParentHash must be identical for clean vs. legacy-annotated authorization"
  );
});

// ─── 6. Independent implementation can reproduce delegationParentHash ──────────

test("delegationParentHash: independent implementation (normative fields only) produces same hash", () => {
  const clean = makeCleanAuth();

  // Simulate an independent implementation that only knows the normative fields.
  // It reconstructs the public artifact manually — no access to Authorization internals.
  const independentPublicArtifact: Record<string, unknown> = {
    auth_id:      clean.auth_id,
    issuer:       clean.issuer,
    audience:     clean.audience,
    intent_hash:  clean.intent_hash,
    state_hash:   clean.state_hash,
    policy_id:    clean.policy_id,
    decision:     clean.decision,
    issued_at:    clean.issued_at,
    expiry:       clean.expiry,
    alg:          clean.alg,
    kid:          clean.kid,
    signature:    clean.signature,
  };

  const independentHash = createHash("sha256")
    .update(canonicalJson(independentPublicArtifact), "utf8")
    .digest("hex");

  const sdkHash = delegationParentHash(clean);

  assert.equal(
    independentHash,
    sdkHash,
    "independent implementation using only normative fields must produce the same delegationParentHash"
  );
});

// ─── 7. delegationParentHash is stable (same input → same output) ─────────────

test("delegationParentHash: deterministic for the same input", () => {
  const clean = makeCleanAuth();

  const h1 = delegationParentHash(clean);
  const h2 = delegationParentHash(clean);

  assert.equal(h1, h2, "delegationParentHash must be deterministic");
  assert.match(h1, /^[0-9a-f]{64}$/, "hash must be a lowercase 64-char hex string");
});
