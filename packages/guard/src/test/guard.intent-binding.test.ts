// SPDX-License-Identifier: Apache-2.0
/**
 * guard.intent-binding.test.ts
 *
 * Verifies that OxDeAIGuard enforces deterministic intent canonicalization and
 * binding at the execution boundary (issue #57).
 *
 * Core invariant: SHA256(canonical(intent)) == AuthorizationV1.intent_hash
 * Any mismatch → DENY → no execution.
 *
 * Test IDs: IB-1 through IB-7.
 *
 *   IB-1  Valid flow (real engine)                 → ALLOW, execute called
 *   IB-2  Auth carries wrong intent_hash           → DENY, execute blocked
 *   IB-3  Different action target (tool mismatch)  → DENY, execute blocked
 *   IB-4  Different args (params mismatch)         → DENY, execute blocked
 *   IB-5  Canonically equivalent inputs            → same hash → ALLOW
 *   IB-6  Intent canonicalization failure          → DENY (fail closed)
 *   IB-7  Side-effect isolation on mismatch        → beforeExecute never called
 */

import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE, intentHash, stateSnapshotHash } from "@oxdeai/core";
import type { Authorization, AuthorizationV1, Intent, State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { OxDeAIAuthorizationError } from "../errors.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import { TEST_KEYSET, TEST_KEYPAIR, signAuth } from "./helpers/fixtures.js";
import type { OxDeAIGuardConfig, ProposedAction, StateVersion } from "../types.js";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const ENGINE_SECRET = "test-secret-must-be-at-least-32-chars!!";
const AUDIENCE = "intent-binding-agent";
const AGENT_ID = AUDIENCE;

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1",
    engine_secret: ENGINE_SECRET,
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_issuer: TEST_KEYSET.issuer,
    authorization_audience: AUDIENCE,
    authorization_ttl_seconds: 600,
    authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeState(): State {
  return buildState({
    agent_id: AGENT_ID,
    allow_action_types: ["PROVISION", "PAYMENT", "PURCHASE", "ONCHAIN_TX"],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
}

function makeVersionedStore(initial: State): {
  getState: () => { state: State; version: StateVersion };
  setState: (s: State, v: StateVersion) => boolean;
} {
  let stored = initial;
  let ver: StateVersion = 0;
  return {
    getState: () => ({ state: stored, version: ver }),
    setState: (s, v) => {
      if (v !== ver) return false;
      stored = s;
      ver = (ver as number) + 1;
      return true;
    },
  };
}

/** Fake engine: ignores intent evaluation, returns a pre-crafted auth. */
function makeFakeEngine(auth: AuthorizationV1): PolicyEngine {
  return {
    evaluatePure(_intent: Intent, s: State) {
      return {
        decision: "ALLOW" as const,
        reasons: [] as string[],
        authorization: auth as unknown as Authorization,
        nextState: s,
      };
    },
    computeStateHash: (s: State) => stateSnapshotHash(s),
    computePolicyId: () => auth.policy_id,
    verifyAuthorization: () => ({ valid: true }),
  } as unknown as PolicyEngine;
}

function makeGuard(
  overrides: Partial<OxDeAIGuardConfig> & Pick<OxDeAIGuardConfig, "engine" | "getState" | "setState">
): ReturnType<typeof OxDeAIGuard> {
  return OxDeAIGuard({
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: AUDIENCE,
    ...overrides,
  });
}

// ── Deterministic test actions ────────────────────────────────────────────────
//
// Fixed intent_id, nonce, and timestampSeconds ensure defaultNormalizeAction
// produces the same Intent on every call, so intent_hash is stable.

// Action A — the baseline action used to issue authorizations.
const ACTION_A: ProposedAction = {
  name: "pay_alice",
  args: { amount: 100, currency: "USD" },
  estimatedCost: 100,
  timestampSeconds: 1_700_000_000,
  context: { agent_id: AGENT_ID, target: "alice", intent_id: "ib-fixed-a", nonce: 42n },
};
const INTENT_HASH_A = intentHash(defaultNormalizeAction(ACTION_A));

// Action B — different target and nonce → different intentHash.
const ACTION_B: ProposedAction = {
  name: "pay_alice",
  args: { amount: 100, currency: "USD" },
  estimatedCost: 100,
  timestampSeconds: 1_700_000_000,
  context: { agent_id: AGENT_ID, target: "bob", intent_id: "ib-fixed-b", nonce: 43n },
};

// Action C — same name/target as A, different args → different metadata_hash.
const ACTION_C: ProposedAction = {
  name: "pay_alice",
  args: { amount: 999, currency: "USD" },
  estimatedCost: 100,
  timestampSeconds: 1_700_000_000,
  context: { agent_id: AGENT_ID, target: "alice", intent_id: "ib-fixed-c", nonce: 42n },
};

// ── IB-1: Valid flow (real engine) → ALLOW ────────────────────────────────────

test("IB-1 valid flow (real engine): execute is called and result returned", async () => {
  const state = makeState();
  const store = makeVersionedStore(state);
  const engine = makeEngine();

  const guard = makeGuard({ engine, ...store });
  // No timestampSeconds: real engine uses current time for issued_at/expiry.
  const freshAction: ProposedAction = {
    name: "pay_alice",
    args: { amount: 100, currency: "USD" },
    estimatedCost: 100,
    context: { agent_id: AGENT_ID, target: "alice" },
  };
  const result = await guard(freshAction, async () => "ib1-ok");

  assert.equal(result, "ib1-ok", "IB-1: guard must return execute() result on ALLOW");
});

// ── IB-2: Auth carries wrong intent_hash → DENY ───────────────────────────────

test("IB-2 wrong intent_hash in auth: OxDeAIAuthorizationError thrown, execute blocked", async () => {
  const state = makeState();
  const store = makeVersionedStore(state);

  // Auth was issued for ACTION_A; guard is called with the different ACTION_B.
  // The fake engine returns the ACTION_A auth regardless of the incoming action.
  const auth = signAuth({
    auth_id: "ib2-auth",
    audience: AUDIENCE,
    state_hash: stateSnapshotHash(state),
    intent_hash: INTENT_HASH_A,
  });
  const guard = makeGuard({ engine: makeFakeEngine(auth), ...store });

  let executed = false;
  await assert.rejects(
    () => guard(ACTION_B, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `IB-2: expected OxDeAIAuthorizationError, got: ${String(err)}`);
      assert.ok(
        err.message.toLowerCase().includes("intent") || err.message.toLowerCase().includes("hash"),
        `IB-2: error message must indicate intent hash mismatch, got: "${err.message}"`
      );
      return true;
    }
  );
  assert.equal(executed, false, "IB-2: execute must not be called on intent hash mismatch");
});

// ── IB-3: Different action target → DENY ─────────────────────────────────────

test("IB-3 different action target: OxDeAIAuthorizationError thrown, execute blocked", async () => {
  const state = makeState();
  const store = makeVersionedStore(state);

  // Auth for ACTION_A (target: "alice"); guard receives ACTION_B (target: "bob").
  const auth = signAuth({
    auth_id: "ib3-auth",
    audience: AUDIENCE,
    state_hash: stateSnapshotHash(state),
    intent_hash: INTENT_HASH_A,
  });
  const guard = makeGuard({ engine: makeFakeEngine(auth), ...store });

  let executed = false;
  await assert.rejects(
    () => guard(ACTION_B, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `IB-3: expected OxDeAIAuthorizationError, got: ${String(err)}`);
      return true;
    }
  );
  assert.equal(executed, false, "IB-3: execute must not be called when action target differs");
});

// ── IB-4: Different args (params mismatch) → DENY ────────────────────────────

test("IB-4 different args (params mismatch): OxDeAIAuthorizationError thrown, execute blocked", async () => {
  const state = makeState();
  const store = makeVersionedStore(state);

  // Auth for ACTION_A (amount: 100); guard receives ACTION_C (amount: 999).
  const auth = signAuth({
    auth_id: "ib4-auth",
    audience: AUDIENCE,
    state_hash: stateSnapshotHash(state),
    intent_hash: INTENT_HASH_A,
  });
  const guard = makeGuard({ engine: makeFakeEngine(auth), ...store });

  let executed = false;
  await assert.rejects(
    () => guard(ACTION_C, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `IB-4: expected OxDeAIAuthorizationError, got: ${String(err)}`);
      return true;
    }
  );
  assert.equal(executed, false, "IB-4: execute must not be called when args differ");
});

// ── IB-5: Canonically equivalent inputs → same hash → ALLOW ──────────────────

test("IB-5 canonically equivalent inputs: same intentHash, execution allowed", async () => {
  // ACTION_A_ALT has args in swapped key order but same content.
  // hashArgs (in normalizeAction) sorts keys before hashing, so metadata_hash is identical.
  const ACTION_A_ALT: ProposedAction = {
    name: "pay_alice",
    args: { currency: "USD", amount: 100 },  // swapped insertion order
    estimatedCost: 100,
    timestampSeconds: 1_700_000_000,
    context: { agent_id: AGENT_ID, target: "alice", intent_id: "ib-fixed-a", nonce: 42n },
  };

  const altHash = intentHash(defaultNormalizeAction(ACTION_A_ALT));
  assert.equal(altHash, INTENT_HASH_A,
    "IB-5 precondition: canonically equivalent inputs must produce the same intentHash");

  const state = makeState();
  const store = makeVersionedStore(state);
  const auth = signAuth({
    auth_id: "ib5-auth",
    audience: AUDIENCE,
    state_hash: stateSnapshotHash(state),
    intent_hash: INTENT_HASH_A,
  });
  const guard = makeGuard({ engine: makeFakeEngine(auth), ...store });

  let executed = false;
  const result = await guard(ACTION_A_ALT, async () => { executed = true; return "ib5-ok"; });

  assert.equal(executed, true, "IB-5: execute must be called for canonically equivalent input");
  assert.equal(result, "ib5-ok");
});

// ── IB-6: Intent canonicalization failure → fail closed ───────────────────────

test("IB-6 intent canonicalization failure: OxDeAIAuthorizationError thrown, execute blocked", async () => {
  const state = makeState();
  const store = makeVersionedStore(state);

  // A getter that throws — when canonicalize() enumerates keys and reads this
  // property, it propagates the error up through intentHash().
  const nonSerializable: Record<string, unknown> = {};
  Object.defineProperty(nonSerializable, "secret", {
    get() { throw new Error("CANNOT_SERIALIZE"); },
    enumerable: true,
  });

  // Custom mapper that injects the non-serializable field into "tool_call",
  // which is one of the INTENT_BINDING_FIELDS used by intentHash().
  const customMapper = (_action: ProposedAction): Intent => ({
    type: "EXECUTE",
    intent_id: "ib6-fixed",
    agent_id: AGENT_ID,
    action_type: "PROVISION",
    amount: 0n,
    target: "test",
    timestamp: 1_700_000_000,
    metadata_hash: "a".repeat(64),
    nonce: 1n,
    signature: "placeholder",
    tool_call: nonSerializable,
  } as unknown as Intent);

  // Fake engine bypasses evaluatePure's own intentHash call so the bad intent
  // reaches the guard's step-6d check unmodified.
  const auth = signAuth({ auth_id: "ib6-auth", audience: AUDIENCE });
  const guard = OxDeAIGuard({
    engine: makeFakeEngine(auth),
    mapActionToIntent: customMapper,
    ...store,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: AUDIENCE,
  });

  let executed = false;
  await assert.rejects(
    () => guard(ACTION_A, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `IB-6: expected OxDeAIAuthorizationError, got: ${String(err)}`);
      assert.ok(
        err.message.includes("canonicalization") || err.message.includes("CANNOT_SERIALIZE"),
        `IB-6: error must indicate canonicalization failure, got: "${err.message}"`
      );
      return true;
    }
  );
  assert.equal(executed, false, "IB-6: execute must not be called when intent canonicalization fails");
});

// ── IB-7: Side-effect isolation — beforeExecute never reached on mismatch ─────

test("IB-7 intent hash mismatch: beforeExecute and execute are never invoked", async () => {
  const state = makeState();
  const store = makeVersionedStore(state);

  // Auth for ACTION_A; guard called with ACTION_B → mismatch → DENY before execution.
  const auth = signAuth({
    auth_id: "ib7-auth",
    audience: AUDIENCE,
    state_hash: stateSnapshotHash(state),
    intent_hash: INTENT_HASH_A,
  });

  let beforeExecuteCalled = false;
  let executeCalled = false;

  const guard = OxDeAIGuard({
    engine: makeFakeEngine(auth),
    ...store,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: AUDIENCE,
    beforeExecute: async () => { beforeExecuteCalled = true; },
  });

  await guard(ACTION_B, async () => { executeCalled = true; }).catch(() => { /* expected */ });

  assert.equal(executeCalled, false,
    "IB-7: execute must not be called on intent hash mismatch");
  assert.equal(beforeExecuteCalled, false,
    "IB-7: beforeExecute must not be called on intent hash mismatch");
});
