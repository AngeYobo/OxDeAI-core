// SPDX-License-Identifier: Apache-2.0
/**
 * guard.replay-store.redis.test.ts
 *
 * Tests for createRedisReplayStore.
 *
 * No real Redis instance is required. A FakeRedisClient mirrors the exact
 * atomic semantics of SET NX EX: a Map<key, expiry> is the backing store,
 * and SET NX is implemented as a single check-and-insert with no window
 * between the check and the write. This faithfully models what Redis does.
 *
 * Coverage:
 *   RS-R1  First consumeAuthId → true
 *   RS-R2  Second consumeAuthId (same id) → false (replay)
 *   RS-R3  After TTL elapses, key is reusable (first-use returns true again)
 *   RS-R4  Concurrent calls: exactly one returns true (atomic NX semantics)
 *   RS-R5  consumeDelegationId: first use → true; replay → false
 *   RS-R6  Redis error in consumeAuthId → throws (fail-closed)
 *   RS-R7  Redis error in consumeDelegationId → throws (fail-closed)
 *   RS-R8  Multiple guard instances sharing one client: cross-instance replay blocked
 *   RS-R9  createRedisReplayStore rejects invalid client at construction time
 */

import test from "node:test";
import assert from "node:assert/strict";

import { createRedisReplayStore } from "../replayStore.redis.js";
import type { RedisClient } from "../replayStore.redis.js";
import { OxDeAIGuard } from "../index.js";
import type { OxDeAIGuardConfig, ProposedAction } from "../index.js";
import { OxDeAIAuthorizationError } from "../errors.js";
import type { Authorization, AuthorizationV1, Intent, State } from "@oxdeai/core";
import { stateSnapshotHash, intentHash } from "@oxdeai/core";
import { defaultNormalizeAction } from "../normalizeAction.js";
import { TEST_KEYSET, signAuth, DELEGATION_AUTHORITIES } from "./helpers/fixtures.js";

// ---------------------------------------------------------------------------
// FakeRedisClient
//
// Implements RedisClient with in-memory Map that mirrors exact Redis NX EX
// semantics. The SET NX operation is synchronous within a single JS turn,
// so it is race-free (JS event loop is single-threaded). This matches the
// atomicity guarantee Redis provides via its single-threaded command processor.
// ---------------------------------------------------------------------------

class FakeRedisClient implements RedisClient {
  /** key → absolute expiry timestamp (seconds). 0 = no expiry. */
  private readonly store = new Map<string, number>();
  /** Simulated clock offset in seconds (for TTL expiry tests). */
  private clockOffset = 0;

  private now(): number {
    return Math.floor(Date.now() / 1000) + this.clockOffset;
  }

  /** Advance the simulated clock by `seconds`. Causes expired keys to be evicted. */
  advanceClock(seconds: number): void {
    this.clockOffset += seconds;
    // Evict expired keys eagerly so subsequent SET NX can succeed.
    const now = this.now();
    for (const [key, expiry] of this.store) {
      if (expiry > 0 && now >= expiry) {
        this.store.delete(key);
      }
    }
  }

  async set(
    key: string,
    value: string,
    nx: "NX",
    ex: "EX",
    seconds: number
  ): Promise<"OK" | null> {
    const now = this.now();

    // Evict the key if it has expired (lazy eviction path for non-advancing tests).
    const existing = this.store.get(key);
    if (existing !== undefined && existing > 0 && now >= existing) {
      this.store.delete(key);
    }

    if (this.store.has(key)) {
      return null; // NX: key already exists
    }

    const expiry = seconds > 0 ? now + seconds : 0;
    this.store.set(key, expiry);
    return "OK";
  }

  /** Expose internal store size for assertions. */
  size(): number { return this.store.size; }
}

/** A FakeRedisClient that throws on every SET call. */
class ErrorRedisClient implements RedisClient {
  constructor(private readonly message: string) {}
  async set(): Promise<"OK" | null> {
    throw new Error(this.message);
  }
}

// ---------------------------------------------------------------------------
// Guard integration helpers (mirrors guard.replay-store.test.ts pattern)
// ---------------------------------------------------------------------------

function makeBaseState(): State {
  return {
    policy_version: "policy-redis",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: { budget_limit: { "agent-redis": 1_000_000n }, spent_in_period: { "agent-redis": 0n } },
    max_amount_per_action: { "agent-redis": 1_000_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-redis": 10 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-redis": 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { "agent-redis": 100 }, calls: {} },
  };
}

const REDIS_FIXED_ACTION: ProposedAction = {
  name: "pay",
  args: { amount: 1 },
  estimatedCost: 0,
  timestampSeconds: 1_700_000_000,
  context: { agent_id: "agent-redis", target: "vendor", intent_id: "redis-fixed-intent", nonce: 1n },
};
const REDIS_INTENT_HASH = intentHash(defaultNormalizeAction(REDIS_FIXED_ACTION));

function makeAction(): ProposedAction {
  return REDIS_FIXED_ACTION;
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
    computePolicyId: () => auth.policy_id,
  };
}

function makeGuardConfig(
  auth: AuthorizationV1,
  redisClient: RedisClient,
  stateOverride?: { get: () => State; set: (s: State) => void }
): OxDeAIGuardConfig {
  let storedState = makeBaseState();
  let storedVersion = 0;
  const get = stateOverride?.get ?? (() => storedState);
  const set = stateOverride?.set ?? ((s: State) => { storedState = s; });
  return {
    engine: makeFakeEngine(auth) as any,
    getState: async () => ({ state: get(), version: storedVersion }),
    setState: async (s, v) => {
      if (v !== storedVersion) return false;
      set(s);
      storedVersion++;
      return true;
    },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
    replayStore: createRedisReplayStore({ client: redisClient }),
  };
}

// ---------------------------------------------------------------------------
// RS-R1: First consumeAuthId → true
// ---------------------------------------------------------------------------

test("RS-R1 first consumeAuthId via guard: execution succeeds", async () => {
  const fake = new FakeRedisClient();
  const auth = signAuth({ auth_id: "redis-auth-r1", state_hash: stateSnapshotHash(makeBaseState()), intent_hash: REDIS_INTENT_HASH });
  const guard = OxDeAIGuard(makeGuardConfig(auth, fake));

  let executed = false;
  await guard(makeAction(), async () => { executed = true; });
  assert.ok(executed);
});

// ---------------------------------------------------------------------------
// RS-R2: Second consumeAuthId (same id) → false (replay)
// ---------------------------------------------------------------------------

test("RS-R2 second consumeAuthId via guard: replay blocked", async () => {
  const fake = new FakeRedisClient();
  const auth = signAuth({ auth_id: "redis-auth-r2", state_hash: stateSnapshotHash(makeBaseState()), intent_hash: REDIS_INTENT_HASH });
  const guard = OxDeAIGuard(makeGuardConfig(auth, fake));
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
// RS-R3: After TTL elapses, key is reusable
// ---------------------------------------------------------------------------

test("RS-R3 after TTL expiry, key can be re-consumed (store level)", async () => {
  const fake = new FakeRedisClient();
  const store = createRedisReplayStore({ client: fake });
  const now = Math.floor(Date.now() / 1000);

  // First consume: expiry 2 seconds from now → TTL = 2
  const first = await store.consumeAuthId("r3-id", { expiry: now + 2 });
  assert.equal(first, true);

  // Second consume before expiry: replay
  const second = await store.consumeAuthId("r3-id", { expiry: now + 2 });
  assert.equal(second, false);

  // Advance fake clock past the TTL
  fake.advanceClock(3);

  // After eviction, the same id can be consumed again
  const third = await store.consumeAuthId("r3-id", { expiry: now + 10 });
  assert.equal(third, true);
});

// ---------------------------------------------------------------------------
// RS-R4: Concurrent calls — exactly one returns true (NX atomicity)
// ---------------------------------------------------------------------------

test("RS-R4 concurrent consumeAuthId: exactly one succeeds", async () => {
  const fake = new FakeRedisClient();
  const store = createRedisReplayStore({ client: fake });
  const now = Math.floor(Date.now() / 1000);

  // Fire 20 concurrent consume calls for the same id.
  const results = await Promise.all(
    Array.from({ length: 20 }, () =>
      store.consumeAuthId("r4-id", { expiry: now + 300 })
    )
  );

  const trueCount = results.filter(Boolean).length;
  const falseCount = results.filter((r) => !r).length;
  assert.equal(trueCount, 1, "exactly one call must win the NX race");
  assert.equal(falseCount, 19, "all other callers must see replay");
});

// ---------------------------------------------------------------------------
// RS-R5: consumeDelegationId: first use → true; replay → false
// ---------------------------------------------------------------------------

test("RS-R5 consumeDelegationId: first use true, replay false", async () => {
  const fake = new FakeRedisClient();
  const store = createRedisReplayStore({ client: fake });
  const now = Math.floor(Date.now() / 1000);

  const first = await store.consumeDelegationId!("r5-del-id", { expiry: now + 300 });
  assert.equal(first, true);

  const second = await store.consumeDelegationId!("r5-del-id", { expiry: now + 300 });
  assert.equal(second, false);
});

// ---------------------------------------------------------------------------
// RS-R6: Redis error in consumeAuthId → throws (fail-closed)
// ---------------------------------------------------------------------------

test("RS-R6 Redis error in consumeAuthId: throws OxDeAIAuthorizationError via guard", async () => {
  const errClient = new ErrorRedisClient("connection refused");
  const auth = signAuth({ auth_id: "redis-auth-r6" });
  const guard = OxDeAIGuard(makeGuardConfig(auth, errClient));

  let executed = false;
  await assert.rejects(
    () => guard(makeAction(), async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /[Rr]eplay store unavailable/);
      assert.match(err.message, /connection refused/);
      return true;
    }
  );

  assert.equal(executed, false, "execute must not be called when Redis throws");
});

// ---------------------------------------------------------------------------
// RS-R7: Redis error in consumeDelegationId → throws (fail-closed)
// ---------------------------------------------------------------------------

test("RS-R7 Redis error in consumeDelegationId: throws OxDeAIAuthorizationError via guard", async () => {
  // consumeAuthId passes (won't be reached — delegation_id is checked first),
  // but consumeDelegationId throws.
  const hybridClient: RedisClient = {
    async set(key: string): Promise<"OK" | null> {
      if (key.startsWith("replay:delegation:")) {
        throw new Error("replica read-only");
      }
      return "OK";
    },
  };

  const { makeParentAuthWithScope, makeDelegationWithScope } = await import("./helpers/fixtures.js");
  const parentAuth = makeParentAuthWithScope(
    { tools: ["pay"], max_amount: 1_000_000n },
    { auth_id: "redis-parent-r7", audience: "agent-redis" }
  );
  const delegation = makeDelegationWithScope(parentAuth, { tools: ["pay"], max_amount: 1_000_000n });

  const guard = OxDeAIGuard({
    engine: { evaluatePure: () => { throw new Error("should not reach engine"); }, computePolicyId: () => "unused-on-delegation-path" } as any,
    getState: async () => ({ state: makeBaseState(), version: 0 }),
    setState: async () => true,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "agent-redis",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
    replayStore: createRedisReplayStore({ client: hybridClient }),
  });

  let executed = false;
  await assert.rejects(
    () => guard(makeAction(), async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: { tools: ["pay"], max_amount: 1_000_000n } } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /[Rr]eplay store unavailable/);
      assert.match(err.message, /replica read-only/);
      return true;
    }
  );

  assert.equal(executed, false);
});

// ---------------------------------------------------------------------------
// RS-R8: Multiple guard instances sharing one Redis client: cross-instance replay
// ---------------------------------------------------------------------------

test("RS-R8 shared Redis client: replay blocked across two distinct guard instances", async () => {
  // Simulates two processes sharing a Redis cluster via a shared FakeRedisClient.
  const sharedFake = new FakeRedisClient();
  const auth = signAuth({ auth_id: "redis-auth-r8", state_hash: stateSnapshotHash(makeBaseState()), intent_hash: REDIS_INTENT_HASH });

  const sharedStore = createRedisReplayStore({ client: sharedFake });

  let stateA = makeBaseState();
  let versionA = 0;
  const guardA = OxDeAIGuard({
    engine: makeFakeEngine(auth) as any,
    getState: async () => ({ state: stateA, version: versionA }),
    setState: async (s, v) => { if (v !== versionA) return false; stateA = s; versionA++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
    replayStore: sharedStore,
  });

  let stateB = makeBaseState();
  let versionB = 0;
  const guardB = OxDeAIGuard({
    engine: makeFakeEngine(auth) as any,
    getState: async () => ({ state: stateB, version: versionB }),
    setState: async (s, v) => { if (v !== versionB) return false; stateB = s; versionB++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
    replayStore: sharedStore,
  });

  let executions = 0;
  await guardA(makeAction(), async () => { executions++; });

  // guardB reuses the same auth_id → replay detected via shared fake.
  await assert.rejects(
    () => guardB(makeAction(), async () => { executions++; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.match(err.message, /replay detected/i);
      return true;
    }
  );

  assert.equal(executions, 1, "only the first instance's execute must run");
});

// ---------------------------------------------------------------------------
// RS-R9: createRedisReplayStore rejects invalid client at construction time
// ---------------------------------------------------------------------------

test("RS-R9 createRedisReplayStore throws on invalid client", () => {
  assert.throws(
    () => createRedisReplayStore({ client: null as any }),
    (err: unknown) => {
      assert.ok(err instanceof TypeError);
      assert.match(err.message, /RedisClient/);
      return true;
    }
  );

  assert.throws(
    () => createRedisReplayStore({ client: {} as any }),
    (err: unknown) => {
      assert.ok(err instanceof TypeError);
      return true;
    }
  );
});
