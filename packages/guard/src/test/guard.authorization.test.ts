// SPDX-License-Identifier: Apache-2.0
/**
 * guard.authorization.test.ts
 *
 * Verifies that OxDeAIGuard enforces strict AuthorizationV1 verification
 * on the standard (non-delegation) path.
 *
 * Test IDs: A-1 through A-6, plus A-8/A-9 (#316 same-producer provenance).
 *
 *   A-1  Tampered signature → OxDeAIAuthorizationError, execute blocked
 *   A-2  Unknown issuer     → OxDeAIAuthorizationError, execute blocked
 *   A-3  Wrong audience     → OxDeAIAuthorizationError, execute blocked
 *   A-4  Expired auth       → OxDeAIAuthorizationError, execute blocked
 *   A-5  Missing trustedKeySets → OxDeAIGuardConfigurationError at construction
 *   A-6  Valid auth         → execute runs, result returned
 *   A-8  Same-producer construction: artifact policy_id == engine.computePolicyId()
 *   A-9  validateConfig requires only what the execution path consumes
 */

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { signAuthorizationEd25519, stateSnapshotHash, intentHash } from "@oxdeai/core";
import type { Authorization, AuthorizationV1, Intent, State } from "@oxdeai/core";

import { OxDeAIGuard } from "../guard.js";
import { OxDeAIAuthorizationError, OxDeAIGuardConfigurationError } from "../errors.js";
import { TEST_KEYSET, TEST_KEYPAIR, signAuth } from "./helpers/fixtures.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import type { OxDeAIGuardConfig, ProposedAction } from "../types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const T_NOW = Math.floor(Date.now() / 1000);

function makeBaseState(): State {
  return {
    policy_version: "policy-auth",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: { budget_limit: { "agent-auth": 1_000_000n }, spent_in_period: { "agent-auth": 0n } },
    max_amount_per_action: { "agent-auth": 1_000_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-auth": 10 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-auth": 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { "agent-auth": 100 }, calls: {} },
  };
}

function makeFakeEngine(auth: AuthorizationV1) {
  return {
    evaluatePure(_intent: Intent, state: State) {
      return {
        decision: "ALLOW" as const,
        reasons: [],
        authorization: auth as Authorization,
        nextState: state,
      };
    },
    computeStateHash: (state: State) => stateSnapshotHash(state),
  };
}

function makeGuardConfig(auth: AuthorizationV1, overrides?: Partial<OxDeAIGuardConfig>): OxDeAIGuardConfig {
  let storedState = makeBaseState();
  let storedVersion = 0;
  return {
    engine: makeFakeEngine(auth) as any,
    getState: async () => ({ state: storedState, version: storedVersion }),
    setState: async (s, v) => { if (v !== storedVersion) return false; storedState = s; storedVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    ...overrides,
  };
}

// Fixed intent_id and nonce make defaultNormalizeAction deterministic so
// FIXED_INTENT_HASH matches what the guard computes at runtime.
const ACTION: ProposedAction = {
  name: "provision_gpu",
  args: { asset: "a100" },
  estimatedCost: 0,
  context: { agent_id: "agent-auth", target: "gpu-pool", intent_id: "auth-fixed-intent-id", nonce: 1n },
  timestampSeconds: T_NOW,
};
const FIXED_INTENT_HASH = intentHash(defaultNormalizeAction(ACTION));

// ---------------------------------------------------------------------------
// A-1: Tampered signature → OxDeAIAuthorizationError, execute blocked
// ---------------------------------------------------------------------------

test("A-1 tampered signature: execute is blocked and OxDeAIAuthorizationError is thrown", async () => {
  // Sign a valid auth, then corrupt the signature byte.
  const valid = signAuth({ auth_id: "a1-auth", audience: "aud-test" });
  const tampered: AuthorizationV1 = { ...valid, signature: "0".repeat(88) };

  const guard = OxDeAIGuard(makeGuardConfig(tampered));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${err}`);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when signature is invalid");
});

// ---------------------------------------------------------------------------
// A-2: Unknown issuer → OxDeAIAuthorizationError, execute blocked
// ---------------------------------------------------------------------------

test("A-2 unknown issuer: execute is blocked and OxDeAIAuthorizationError is thrown", async () => {
  // Sign with a separate key pair under an issuer not in TEST_KEYSET.
  const unknownKeys = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const auth = signAuthorizationEd25519(
    {
      auth_id: "a2-auth",
      issuer: "unknown-issuer",
      audience: "aud-test",
      intent_hash: "i".repeat(64),
      state_hash: "s".repeat(64),
      policy_id: "p".repeat(64),
      decision: "ALLOW",
      issued_at: T_NOW - 60,
      expiry: T_NOW + 600,
      kid: "k-unknown",
      nonce: "1",
      capability: "exec",
    },
    unknownKeys.privateKey
  ) as AuthorizationV1;

  const guard = OxDeAIGuard(makeGuardConfig(auth));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${err}`);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when issuer is unknown");
});

// ---------------------------------------------------------------------------
// A-3: Wrong audience → OxDeAIAuthorizationError, execute blocked
// ---------------------------------------------------------------------------

test("A-3 wrong audience: execute is blocked and OxDeAIAuthorizationError is thrown", async () => {
  // auth is signed for "agent-other", but expectedAudience is "aud-test".
  const auth = signAuth({ auth_id: "a3-auth", audience: "agent-other" });

  const guard = OxDeAIGuard(makeGuardConfig(auth));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${err}`);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when audience does not match expectedAudience");
});

// ---------------------------------------------------------------------------
// A-4: Expired auth → OxDeAIAuthorizationError, execute blocked
// ---------------------------------------------------------------------------

test("A-4 expired auth: execute is blocked and OxDeAIAuthorizationError is thrown", async () => {
  const expiry = T_NOW - 60; // expired 1 minute ago
  const auth = signAuth({ auth_id: "a4-auth", audience: "aud-test", expiry });

  const guard = OxDeAIGuard(makeGuardConfig(auth));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${err}`);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when auth is expired");
});

// ---------------------------------------------------------------------------
// A-5: Missing trustedKeySets → OxDeAIGuardConfigurationError at construction
// ---------------------------------------------------------------------------

test("A-5 missing trustedKeySets: OxDeAIGuardConfigurationError thrown at construction", () => {
  const auth = signAuth({ auth_id: "a5-auth" });

  assert.throws(
    () => {
      OxDeAIGuard({
        engine: makeFakeEngine(auth) as any,
        getState: async () => ({ state: makeBaseState(), version: 0 }),
        setState: async () => true,
        expectedAudience: "aud-test",
        // trustedKeySets intentionally omitted
      } as any);
    },
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIGuardConfigurationError,
        `expected OxDeAIGuardConfigurationError, got: ${err}`);
      return true;
    }
  );
});

// ---------------------------------------------------------------------------
// A-6: Valid auth → execute runs, result returned
// ---------------------------------------------------------------------------

test("A-6 valid auth: execute runs and result is returned", async () => {
  const auth = signAuth({ auth_id: "a6-auth", audience: "aud-test", state_hash: stateSnapshotHash(makeBaseState()), intent_hash: FIXED_INTENT_HASH });
  const guard = OxDeAIGuard(makeGuardConfig(auth));

  let executed = false;
  const result = await guard(ACTION, async () => { executed = true; return "ok"; });

  assert.ok(executed, "execute must be called for a valid authorization");
  assert.equal(result, "ok");
});

// ---------------------------------------------------------------------------
// A-8 / A-9: same-producer provenance (#316)
// ---------------------------------------------------------------------------

test("A-8 same-producer construction: evaluatePure().authorization.policy_id equals engine.computePolicyId()", async () => {
  // Pins WHY recomputing an expectation from `config.engine` was not an
  // independent check. A real PolicyEngine derives `authorization.policy_id`
  // from the same policy configuration that `computePolicyId()` reads, so both
  // values come from one producer and one derivation.
  //
  // Verifying an artifact against a value recomputed from its own producer
  // restates that producer's derivation; it establishes no constraint that an
  // independent authority would impose. That is the defect #316 removes, and
  // it is why the expectation was deleted rather than re-sourced.
  const { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } = await import("@oxdeai/core");
  const engine = new PolicyEngine({
    // must match makeBaseState().policy_version, or the engine DENYs on version.
    policy_version: "policy-auth",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_issuer: TEST_KEYSET.issuer,
    authorization_audience: "agent-auth",
    authorization_ttl_seconds: 600,
    authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });

  const state = makeBaseState();
  const intent = defaultNormalizeAction(ACTION);
  const out = engine.evaluatePure(intent, state, T_NOW);

  assert.equal(out.decision, "ALLOW", `expected ALLOW, got ${out.decision}: ${JSON.stringify(out.reasons)}`);
  assert.ok(out.authorization, "engine must emit an authorization on ALLOW");
  assert.equal(
    out.authorization!.policy_id,
    engine.computePolicyId(),
    "the artifact's policy_id and the engine's recomputed policy id are the SAME producer's value; " +
      "comparing them cannot establish independent policy authority"
  );
});

test("A-9 validateConfig requires only what the execution path consumes: an engine without computePolicyId is accepted", () => {
  // Scoped claim: validateConfig no longer demands a capability solely to
  // support the removed comparison. It is NOT a compatibility promise that
  // arbitrary custom or duck-typed engines are a supported public extension
  // surface — `OxDeAIGuardConfig.engine` remains typed as `PolicyEngine`.
  const auth = signAuth({
    auth_id: "a9-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(makeBaseState()),
    intent_hash: FIXED_INTENT_HASH,
  });

  const engineWithoutComputePolicyId = {
    evaluatePure(_intent: Intent, state: State) {
      return { decision: "ALLOW" as const, reasons: [], authorization: auth as Authorization, nextState: state };
    },
    computeStateHash: (state: State) => stateSnapshotHash(state),
  };
  assert.equal(
    (engineWithoutComputePolicyId as { computePolicyId?: unknown }).computePolicyId,
    undefined,
    "fixture must genuinely lack the method for this test to mean anything"
  );

  assert.doesNotThrow(() =>
    OxDeAIGuard(makeGuardConfig(auth, { engine: engineWithoutComputePolicyId as never }))
  );
});
