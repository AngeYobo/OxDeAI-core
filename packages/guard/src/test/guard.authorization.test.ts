// SPDX-License-Identifier: Apache-2.0
/**
 * guard.authorization.test.ts
 *
 * Verifies that OxDeAIGuard enforces strict AuthorizationV1 verification
 * on the standard (non-delegation) path.
 *
 * Test IDs: A-1 through A-6.
 *
 *   A-1  Tampered signature → OxDeAIAuthorizationError, execute blocked
 *   A-2  Unknown issuer     → OxDeAIAuthorizationError, execute blocked
 *   A-3  Wrong audience     → OxDeAIAuthorizationError, execute blocked
 *   A-4  Expired auth       → OxDeAIAuthorizationError, execute blocked
 *   A-5  Missing trustedKeySets → OxDeAIGuardConfigurationError at construction
 *   A-6  Valid auth         → execute runs, result returned
 */

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { signAuthorizationEd25519, stateSnapshotHash, intentHash } from "@oxdeai/core";
import type { Authorization, AuthorizationV1, Intent, State } from "@oxdeai/core";

import { OxDeAIGuard } from "../guard.js";
import { OxDeAIAuthorizationError, OxDeAIGuardConfigurationError } from "../errors.js";
import { TEST_KEYSET, signAuth } from "./helpers/fixtures.js";
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

/**
 * @param enginePolicyId Policy identity this engine's trusted configuration
 *   establishes. Defaults to the artifact's own `policy_id` so existing cases
 *   keep their meaning, but it is a SEPARATE input on purpose: the guard
 *   verifies `authorization.policy_id` against `engine.computePolicyId()`
 *   (#301), and a helper that always returned the artifact's own value could
 *   never exercise that comparison.
 */
function makeFakeEngine(auth: AuthorizationV1, enginePolicyId: string = auth.policy_id) {
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
    computePolicyId: () => enginePolicyId,
  };
}

function makeGuardConfig(
  auth: AuthorizationV1,
  overrides?: Partial<OxDeAIGuardConfig>,
  enginePolicyId?: string
): OxDeAIGuardConfig {
  let storedState = makeBaseState();
  let storedVersion = 0;
  return {
    engine: makeFakeEngine(auth, enginePolicyId) as any,
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

// ---------------------------------------------------------------------------
// A-7: policy_id is checked against TRUSTED ENGINE CONFIGURATION (#301)
// ---------------------------------------------------------------------------

test("A-7 policy_id mismatch against engine.computePolicyId(): execute blocked", async () => {
  // Everything else about this artifact is valid: correctly signed, correct
  // audience, correct intent and state binding, unexpired. The ONLY defect is
  // that its policy_id is not the policy this engine is configured for.
  //
  // Before #301 the guard passed `expectedPolicyId: authorization.policy_id`,
  // comparing the artifact with itself, so this case could not fail. It now
  // compares against `engine.computePolicyId()`, established from trusted
  // engine configuration before the artifact exists.
  const ARTIFACT_POLICY = "P2-artifact-policy";
  const ENGINE_POLICY = "P1-engine-policy";
  assert.notEqual(ARTIFACT_POLICY, ENGINE_POLICY);

  const auth = signAuth({
    auth_id: "a7-policy-mismatch",
    audience: "aud-test",
    state_hash: stateSnapshotHash(makeBaseState()),
    intent_hash: FIXED_INTENT_HASH,
    policy_id: ARTIFACT_POLICY,
  });
  const guard = OxDeAIGuard(makeGuardConfig(auth, undefined, ENGINE_POLICY));

  let executed = false;
  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; return "ok"; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError, `expected OxDeAIAuthorizationError, got ${String(err)}`);
      assert.match(
        String((err as Error).message),
        /AUTH_POLICY_ID_MISMATCH/,
        "must fail specifically on the policy-id binding"
      );
      return true;
    }
  );
  assert.equal(executed, false, "execute must never run for a foreign policy_id");
});

test("A-7b matching engine policy id still executes (a real check, not blanket denial)", async () => {
  const POLICY = "P1-engine-policy";
  const auth = signAuth({
    auth_id: "a7b-policy-match",
    audience: "aud-test",
    state_hash: stateSnapshotHash(makeBaseState()),
    intent_hash: FIXED_INTENT_HASH,
    policy_id: POLICY,
  });
  const guard = OxDeAIGuard(makeGuardConfig(auth, undefined, POLICY));

  let executed = false;
  const result = await guard(ACTION, async () => { executed = true; return "ok"; });

  assert.ok(executed, "an artifact matching the engine's configured policy must execute");
  assert.equal(result, "ok");
});

test("A-6 valid auth: execute runs and result is returned", async () => {
  const auth = signAuth({ auth_id: "a6-auth", audience: "aud-test", state_hash: stateSnapshotHash(makeBaseState()), intent_hash: FIXED_INTENT_HASH });
  const guard = OxDeAIGuard(makeGuardConfig(auth));

  let executed = false;
  const result = await guard(ACTION, async () => { executed = true; return "ok"; });

  assert.ok(executed, "execute must be called for a valid authorization");
  assert.equal(result, "ok");
});
