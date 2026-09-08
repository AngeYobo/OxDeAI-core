// SPDX-License-Identifier: Apache-2.0
/**
 * guard.replay-store.test.ts
 *
 * Tests for the pluggable ReplayStore abstraction.
 *
 * Coverage:
 *   RS-1  Default (in-memory) store: auth_id replay blocked within one guard instance
 *   RS-2  Default (in-memory) store: delegation_id replay blocked within one guard instance
 *   RS-3  Shared durable store: auth_id replay blocked across two DIFFERENT guard instances
 *   RS-4  Shared durable store: delegation_id replay blocked across two guard instances
 *   RS-5  Failing consumeAuthId: execution blocked (fail-closed)
 *   RS-6  Failing consumeDelegationId: execution blocked (fail-closed)
 *   RS-7  Store without consumeDelegationId: delegation path still works; parentAuth replay is enforced
 *   RS-8  createInMemoryReplayStore is exported and independently usable
 *   RS-9  Store unavailable for parentAuth: execution blocked on delegation path
 */

import test from "node:test";
import assert from "node:assert/strict";

import type { Authorization, AuthorizationV1, Intent, State } from "@oxdeai/core";
import { stateSnapshotHash, intentHash } from "@oxdeai/core";
import { defaultNormalizeAction } from "../normalizeAction.js";

import { OxDeAIGuard, createInMemoryReplayStore } from "../index.js";
import type { ReplayStore, OxDeAIGuardConfig, ProposedAction } from "../index.js";
import { OxDeAIAuthorizationError } from "../errors.js";
import { TEST_KEYSET, TEST_KEYPAIR, signAuth, makeParentAuthWithScope, makeDelegationWithScope, DELEGATION_AUTHORITIES } from "./helpers/fixtures.js";

// ---------------------------------------------------------------------------
// Shared fixtures

function makeBaseState(): State {
  return {
    policy_version: "policy-rs",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: { budget_limit: { "agent-rs": 1_000_000n }, spent_in_period: { "agent-rs": 0n } },
    max_amount_per_action: { "agent-rs": 1_000_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-rs": 10 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-rs": 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { "agent-rs": 100 }, calls: {} },
  };
}

const RS_FIXED_ACTION: ProposedAction = {
  name: "pay",
  args: { amount: 1 },
  estimatedCost: 0,
  timestampSeconds: 1_700_000_000,
  context: { agent_id: "agent-rs", target: "vendor", intent_id: "rs-fixed-intent", nonce: 1n },
};
const RS_INTENT_HASH = intentHash(defaultNormalizeAction(RS_FIXED_ACTION));

function makeAction(): ProposedAction {
  return RS_FIXED_ACTION;
}

/** A FakeEngine that always ALLOWs with the provided authorization artifact. */
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

function makeGuardConfig(
  auth: AuthorizationV1,
  overrides: Partial<OxDeAIGuardConfig> = {}
): OxDeAIGuardConfig {
  let storedState = makeBaseState();
  let storedVersion = 0;
  return {
    engine: makeFakeEngine(auth) as any,
    getState: async () => ({ state: storedState, version: storedVersion }),
    setState: async (s, v) => { if (v !== storedVersion) return false; storedState = s; storedVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// RS-1: Default in-memory store blocks auth_id replay within one guard instance

test("RS-1 default store: auth_id replay blocked on second call to same guard instance", async () => {
  const auth = signAuth({ auth_id: "rs-auth-1", state_hash: stateSnapshotHash(makeBaseState()), intent_hash: RS_INTENT_HASH });
  const guard = OxDeAIGuard(makeGuardConfig(auth));
  const action = makeAction();

  let executions = 0;
  await guard(action, async () => { executions++; });

  await assert.rejects(
    () => guard(action, async () => { executions++; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /replay detected/i);
      return true;
    }
  );

  assert.equal(executions, 1);
});

// ---------------------------------------------------------------------------
// RS-2: Default in-memory store blocks delegation_id replay within one guard instance

test("RS-2 default store: delegation_id replay blocked on second call to same guard instance", async () => {
  const parentAuth = makeParentAuthWithScope(
    { tools: ["pay"], max_amount: 1_000_000n },
    { auth_id: "rs-parent-auth-2", audience: "agent-rs" }
  );
  const delegation = makeDelegationWithScope(parentAuth, { tools: ["pay"], max_amount: 1_000_000n });

  const guard = OxDeAIGuard({
    engine: { evaluatePure: () => { throw new Error("should not reach engine on delegation path"); } } as any,
    getState: async () => ({ state: makeBaseState(), version: 0 }),
    setState: async () => true,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "agent-rs",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
  });
  const action = makeAction();

  let executions = 0;
  await guard(action, async () => { executions++; }, { delegation: { delegation, parentAuth, parentScope: { tools: ["pay"], max_amount: 1_000_000n } } });

  await assert.rejects(
    () => guard(action, async () => { executions++; }, { delegation: { delegation, parentAuth, parentScope: { tools: ["pay"], max_amount: 1_000_000n } } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /[Dd]elegation replay detected/);
      return true;
    }
  );

  assert.equal(executions, 1);
});

// ---------------------------------------------------------------------------
// RS-3: Shared durable store blocks auth_id replay across different guard instances

test("RS-3 shared store: auth_id replay blocked across two distinct guard instances", async () => {
  // A shared store simulates a durable backend (e.g. Redis) shared between processes.
  const sharedStore = createInMemoryReplayStore();
  const auth = signAuth({ auth_id: "rs-auth-3", state_hash: stateSnapshotHash(makeBaseState()), intent_hash: RS_INTENT_HASH });

  const guardA = OxDeAIGuard(makeGuardConfig(auth, { replayStore: sharedStore }));
  const guardB = OxDeAIGuard(makeGuardConfig(auth, { replayStore: sharedStore }));
  const action = makeAction();

  let executions = 0;
  await guardA(action, async () => { executions++; });

  // guardB has its own in-flight state but shares the replay store → replay detected.
  await assert.rejects(
    () => guardB(action, async () => { executions++; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /replay detected/i);
      return true;
    }
  );

  assert.equal(executions, 1, "only the first guard instance's execute must run");
});

// ---------------------------------------------------------------------------
// RS-4: Shared durable store blocks delegation_id replay across guard instances

test("RS-4 shared store: delegation_id replay blocked across two distinct guard instances", async () => {
  const sharedStore = createInMemoryReplayStore();
  const parentAuth = makeParentAuthWithScope(
    { tools: ["pay"], max_amount: 1_000_000n },
    { auth_id: "rs-parent-auth-4", audience: "agent-rs" }
  );
  const delegation = makeDelegationWithScope(parentAuth, { tools: ["pay"], max_amount: 1_000_000n });

  function makeDelGuard() {
    return OxDeAIGuard({
      engine: { evaluatePure: () => { throw new Error("should not reach engine"); } } as any,
      getState: async () => ({ state: makeBaseState(), version: 0 }),
      setState: async () => true,
      trustedKeySets: [TEST_KEYSET],
      expectedAudience: "agent-rs",
      trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
      replayStore: sharedStore,
    });
  }

  const guardA = makeDelGuard();
  const guardB = makeDelGuard();
  const action = makeAction();

  let executions = 0;
  await guardA(action, async () => { executions++; }, { delegation: { delegation, parentAuth, parentScope: { tools: ["pay"], max_amount: 1_000_000n } } });

  await assert.rejects(
    () => guardB(action, async () => { executions++; }, { delegation: { delegation, parentAuth, parentScope: { tools: ["pay"], max_amount: 1_000_000n } } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /[Dd]elegation replay detected/);
      return true;
    }
  );

  assert.equal(executions, 1, "only the first guard instance's execute must run");
});

// ---------------------------------------------------------------------------
// RS-5: consumeAuthId throws → execution blocked (fail-closed)

test("RS-5 failing consumeAuthId: execution blocked when store throws", async () => {
  const failingStore: ReplayStore = {
    async consumeAuthId(): Promise<boolean> {
      throw new Error("redis unavailable");
    },
  };

  const auth = signAuth({ auth_id: "rs-auth-5" });
  const guard = OxDeAIGuard(makeGuardConfig(auth, { replayStore: failingStore }));
  const action = makeAction();

  let executed = false;
  await assert.rejects(
    () => guard(action, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /[Rr]eplay store unavailable/);
      assert.match(err.message, /redis unavailable/);
      return true;
    }
  );

  assert.equal(executed, false, "execute must not be called when store throws");
});

// ---------------------------------------------------------------------------
// RS-6: consumeDelegationId throws → execution blocked on delegation path

test("RS-6 failing consumeDelegationId: execution blocked when store throws on delegation path", async () => {
  const failingStore: ReplayStore = {
    async consumeAuthId(): Promise<boolean> {
      return true; // auth would pass
    },
    async consumeDelegationId(): Promise<boolean> {
      throw new Error("db connection lost");
    },
  };

  const parentAuth = makeParentAuthWithScope(
    { tools: ["pay"], max_amount: 1_000_000n },
    { auth_id: "rs-parent-auth-6", audience: "agent-rs" }
  );
  const delegation = makeDelegationWithScope(parentAuth, { tools: ["pay"], max_amount: 1_000_000n });

  const guard = OxDeAIGuard({
    engine: { evaluatePure: () => { throw new Error("should not reach engine"); } } as any,
    getState: async () => ({ state: makeBaseState(), version: 0 }),
    setState: async () => true,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "agent-rs",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
    replayStore: failingStore,
  });

  let executed = false;
  await assert.rejects(
    () => guard(makeAction(), async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: { tools: ["pay"], max_amount: 1_000_000n } } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /[Rr]eplay store unavailable/);
      assert.match(err.message, /db connection lost/);
      return true;
    }
  );

  assert.equal(executed, false, "execute must not be called when delegation store throws");
});

// ---------------------------------------------------------------------------
// RS-7: Store without consumeDelegationId — delegation path still enforces parentAuth replay

test("RS-7 store without consumeDelegationId: delegation executes; parentAuth replay is enforced via consumeAuthId", async () => {
  // A store that only implements consumeAuthId (consumeDelegationId is absent).
  // The guard must fall through and still enforce replay via consumeAuthId.
  const authOnlyStore: ReplayStore = {
    async consumeAuthId(authId: string): Promise<boolean> {
      return internalSet.has(authId) ? false : (internalSet.add(authId), true);
    },
    // consumeDelegationId intentionally absent
  };
  const internalSet = new Set<string>();

  const parentAuth = makeParentAuthWithScope(
    { tools: ["pay"], max_amount: 1_000_000n },
    { auth_id: "rs-parent-auth-7", audience: "agent-rs" }
  );
  const delegation = makeDelegationWithScope(parentAuth, { tools: ["pay"], max_amount: 1_000_000n });

  const guard = OxDeAIGuard({
    engine: { evaluatePure: () => { throw new Error("should not reach engine"); } } as any,
    getState: async () => ({ state: makeBaseState(), version: 0 }),
    setState: async () => true,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "agent-rs",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
    replayStore: authOnlyStore,
  });
  const action = makeAction();

  // First call: should succeed.
  let executions = 0;
  await guard(action, async () => { executions++; }, { delegation: { delegation, parentAuth, parentScope: { tools: ["pay"], max_amount: 1_000_000n } } });
  assert.equal(executions, 1);

  // Second call with same parentAuth: consumeAuthId returns false → replay blocked.
  await assert.rejects(
    () => guard(action, async () => { executions++; }, { delegation: { delegation, parentAuth, parentScope: { tools: ["pay"], max_amount: 1_000_000n } } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /replay detected/i);
      return true;
    }
  );
  assert.equal(executions, 1, "parentAuth replay must be blocked even without consumeDelegationId");
});

// ---------------------------------------------------------------------------
// RS-8: createInMemoryReplayStore is exported and independently usable

test("RS-8 createInMemoryReplayStore: exported factory produces an independent working store", async () => {
  const storeA = createInMemoryReplayStore();
  const storeB = createInMemoryReplayStore();

  // storeA: first consume succeeds, second is replay.
  assert.equal(await storeA.consumeAuthId("x", { expiry: 9999999999 }), true);
  assert.equal(await storeA.consumeAuthId("x", { expiry: 9999999999 }), false);

  // storeB is independent: same ID not yet seen.
  assert.equal(await storeB.consumeAuthId("x", { expiry: 9999999999 }), true);

  // Delegation IDs follow the same pattern.
  assert.equal(await storeA.consumeDelegationId!("d1", { expiry: 9999999999 }), true);
  assert.equal(await storeA.consumeDelegationId!("d1", { expiry: 9999999999 }), false);
  assert.equal(await storeB.consumeDelegationId!("d1", { expiry: 9999999999 }), true);
});

// ---------------------------------------------------------------------------
// RS-9: Store unavailable for parentAuth → execution blocked on delegation path

test("RS-9 store unavailable for parentAuth auth_id: execution blocked on delegation path", async () => {
  // consumeAuthId succeeds the first time (for delegation_id path coverage), but
  // throws on the second call (parentAuth.auth_id check).
  let callCount = 0;
  const partialFailStore: ReplayStore = {
    async consumeAuthId(): Promise<boolean> {
      throw new Error("network timeout");
    },
    async consumeDelegationId(): Promise<boolean> {
      callCount++;
      return true; // delegation_id passes fine
    },
  };

  const parentAuth = makeParentAuthWithScope(
    { tools: ["pay"], max_amount: 1_000_000n },
    { auth_id: "rs-parent-auth-9", audience: "agent-rs" }
  );
  const delegation = makeDelegationWithScope(parentAuth, { tools: ["pay"], max_amount: 1_000_000n });

  const guard = OxDeAIGuard({
    engine: { evaluatePure: () => { throw new Error("should not reach engine"); } } as any,
    getState: async () => ({ state: makeBaseState(), version: 0 }),
    setState: async () => true,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "agent-rs",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
    replayStore: partialFailStore,
  });

  let executed = false;
  await assert.rejects(
    () => guard(makeAction(), async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: { tools: ["pay"], max_amount: 1_000_000n } } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /[Rr]eplay store unavailable/);
      assert.match(err.message, /network timeout/);
      return true;
    }
  );

  assert.equal(executed, false, "execute must not be called when parentAuth store check throws");
  assert.equal(callCount, 1, "consumeDelegationId should have been called once before the parentAuth failure");
});
