// SPDX-License-Identifier: Apache-2.0
/**
 * verify.engine-authorization.surface.test.ts
 *
 * Verification-surface descriptors for the LIMITED-SCOPE engine helper
 * `PolicyEngine.verifyAuthorization` (#173). This method authenticates only the
 * engine-HMAC field subset (`intent_hash`, `policy_version`,
 * `state_snapshot_hash`, `decision`, `expires_at`). These tests pin the
 * contract that its result ALWAYS carries the #172 descriptors and makes the
 * limited scope explicit:
 *
 *   - a successful engine-HMAC check reports `signatureVerified: true`,
 *     `verificationMode: "permissive"`, `verificationCoverage:
 *     "engine-hmac-subset"` (never `"authorization-v1-full"`);
 *   - a failed or unperformed HMAC never claims successful verification.
 *
 * The mutation tests below are framed as NON-COVERAGE demonstrations — they
 * pin the boundary between engine-HMAC subset authentication and full
 * AuthorizationV1 enforcement verification. Tolerating an out-of-subset
 * mutation is a documented limitation of this helper, NOT desirable acceptance
 * behavior; relying parties must use the strict standalone verifier.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import { signAuthorizationEd25519, verifyAuthorization } from "../verification/verifyAuthorization.js";
import type { State } from "../types/state.js";
import type { Intent } from "../types/intent.js";
import type { Authorization } from "../types/authorization.js";
import type { KeySet } from "../types/keyset.js";

// ── Fixtures ────────────────────────────────────────────────────────────────

const POLICY = "v-engine-surface";
const T0 = 1_700_000_000;
const TTL = 60;

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: POLICY,
    engine_secret: "engine-surface-secret-32-bytes!!",
    authorization_ttl_seconds: TTL,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeState(): State {
  return {
    policy_version: POLICY,
    period_id: "engine-surface-period",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit:    { "agent-1": 1_000_000n },
      spent_in_period: { "agent-1": 0n },
    },
    max_amount_per_action: { "agent-1": 500_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 100 }, counters: {} },
    replay:   { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-1": 3 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-1": 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { "agent-1": 100 }, calls: {} },
  };
}

function makeIntent(overrides: Partial<Intent> = {}): Intent {
  return {
    intent_id:     "engine-surface-intent-1",
    agent_id:      "agent-1",
    action_type:   "PAYMENT",
    amount:        1_000n,
    target:        "vendor-x",
    timestamp:     T0,
    metadata_hash: "0".repeat(64),
    nonce:         42n,
    signature:     "",
    depth:         0,
    type:          "EXECUTE",
    ...overrides,
  } as Intent;
}

// Issue a valid engine authorization (all engine-HMAC fields authentic).
function issueAuth(engine: PolicyEngine, state: State, intent: Intent): Authorization {
  const out = engine.evaluatePure(intent, state, T0);
  assert.equal(out.decision, "ALLOW", "fixture precondition: intent must ALLOW");
  return out.authorization as Authorization;
}

// ── Strict AuthorizationV1 fixture (for the contrast test) ───────────────────

const KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const KEYSET: KeySet = {
  issuer: "issuer-A",
  version: "1",
  keys: [{ kid: "2026-01", alg: "Ed25519", public_key: KEYPAIR.publicKey }],
};

function makeStrictAuth() {
  return signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: "issuer-A",
      audience: "rp-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "c".repeat(64),
      decision: "ALLOW",
      issued_at: 1000,
      expiry: 1060,
      kid: "2026-01",
      capability: "transfer",
    },
    KEYPAIR.privateKey
  );
}

// ── Baseline: descriptors are always populated on a valid engine result ──────

test("valid engine authorization reports permissive/engine-hmac-subset with signatureVerified true", () => {
  const engine = makeEngine();
  const state = makeState();
  const intent = makeIntent({ nonce: 1n });
  const auth = issueAuth(engine, state, intent);

  const result = engine.verifyAuthorization(intent, auth, state, T0);
  assert.equal(result.valid, true);
  assert.equal(result.signatureVerified, true);
  assert.equal(result.verificationMode, "permissive");
  assert.equal(result.verificationCoverage, "engine-hmac-subset");
  // The engine helper NEVER claims full-authorization coverage.
  assert.notEqual(result.verificationCoverage, "authorization-v1-full");
});

// ── #173 point 1: out-of-subset mutations remain valid (NON-COVERAGE) ────────

test("NON-COVERAGE: mutating audience / capability / state_hash does NOT invalidate the engine result", () => {
  // These fields are OUTSIDE the engine-HMAC subset, so the engine helper does
  // not authenticate them. That the result stays `valid` is the documented
  // limitation this ticket makes explicit — it is NOT an endorsement that the
  // helper is safe as an enforcement gate.
  const engine = makeEngine();
  const state = makeState();
  const intent = makeIntent({ nonce: 2n });
  const auth = issueAuth(engine, state, intent);

  for (const mutated of [
    { ...auth, audience: "attacker-controlled-rp" } as Authorization,
    { ...auth, capability: "escalated-capability" } as Authorization,
    { ...auth, state_hash: "e".repeat(64) } as Authorization,
  ]) {
    const result = engine.verifyAuthorization(intent, mutated, state, T0);
    assert.equal(result.valid, true, "out-of-subset mutation is not detected by the engine helper");
    // ...and the descriptors still honestly report only engine-HMAC-subset coverage,
    // so a caller inspecting them is not misled into treating this as full verification.
    assert.equal(result.signatureVerified, true);
    assert.equal(result.verificationCoverage, "engine-hmac-subset");
  }
});

// ── #173 point 2: the strict verifier REJECTS the same field-class mutations ─

test("CONTRAST: the strict AuthorizationV1 verifier rejects mutations the engine helper tolerates", () => {
  // The same class of fields (audience / capability / state_hash) IS inside the
  // strict AuthorizationV1 signing payload, so the strict verifier rejects any
  // mutation to them — pinning that the engine helper and the strict verifier
  // are NOT interchangeable.
  const signed = makeStrictAuth();
  for (const field of ["audience", "capability", "state_hash"] as const) {
    const forged = { ...signed, [field]: "mutated-value" };
    const strict = verifyAuthorization(forged, {
      now: 1010,
      mode: "strict",
      trustedKeySets: KEYSET,
    });
    assert.equal(strict.ok, false, `strict verifier must reject a mutated ${field}`);
    assert.equal(strict.signatureVerified, false);
    // In strict mode the configured posture is reported as such.
    assert.equal(strict.verificationMode, "strict");
    // The strict verifier evaluated the FULL AuthorizationV1 surface.
    assert.equal(strict.verificationCoverage, "authorization-v1-full");
    assert.ok(strict.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
  }
});

// ── #173 point 3: in-subset mutation must invalidate the engine result ───────

test("in-subset mutation (state_snapshot_hash) invalidates the engine result with signatureVerified false", () => {
  const engine = makeEngine();
  const state = makeState();
  const intent = makeIntent({ nonce: 3n });
  const auth = issueAuth(engine, state, intent);

  // state_snapshot_hash IS inside the engine-HMAC subset → the HMAC check runs
  // and fails. Coverage still reports the surface that was evaluated.
  const mutated = { ...auth, state_snapshot_hash: "f".repeat(64) } as Authorization;
  const result = engine.verifyAuthorization(intent, mutated, state, T0);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "AUTH_SIGNATURE_INVALID");
  assert.equal(result.signatureVerified, false);
  assert.equal(result.verificationMode, "permissive");
  assert.equal(result.verificationCoverage, "engine-hmac-subset");
});

// ── #173 point 4: an invalid engine HMAC reports signatureVerified false ─────

test("a tampered engine_signature reports signatureVerified false (engine-hmac-subset coverage)", () => {
  const engine = makeEngine();
  const state = makeState();
  const intent = makeIntent({ nonce: 4n });
  const auth = issueAuth(engine, state, intent);

  const forged = { ...auth, engine_signature: "0".repeat((auth.engine_signature ?? "").length || 64) } as Authorization;
  const result = engine.verifyAuthorization(intent, forged, state, T0);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "AUTH_SIGNATURE_INVALID");
  assert.equal(result.signatureVerified, false);
  assert.equal(result.verificationCoverage, "engine-hmac-subset");
});

// ── A structural short-circuit runs no HMAC → coverage "none" ────────────────

test("a structural failure before the HMAC check reports coverage none and signatureVerified false", () => {
  const engine = makeEngine();
  const state = makeState();
  const intent = makeIntent({ nonce: 5n });
  const auth = issueAuth(engine, state, intent);

  // Verify past expiry: the expiry short-circuit returns before any HMAC runs.
  const result = engine.verifyAuthorization(intent, auth, state, T0 + TTL + 1);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "AUTH_EXPIRED");
  assert.equal(result.signatureVerified, false);
  assert.equal(result.verificationMode, "permissive");
  assert.equal(result.verificationCoverage, "none");
});
