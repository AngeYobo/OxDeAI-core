// SPDX-License-Identifier: Apache-2.0
/**
 * guard.state-binding.test.ts
 *
 * Verifies that OxDeAIGuard enforces state_hash binding at the PEP boundary:
 * the authorization's state_hash must equal stateSnapshotHash(executionState).
 *
 * Test IDs: SB-1 through SB-13.
 *
 *   SB-1   Matching state_hash         → execute runs, result returned
 *   SB-2   Mismatched state_hash       → OxDeAIAuthorizationError, execute blocked
 *   SB-3   Empty/missing state_hash    → OxDeAIAuthorizationError, execute blocked
 *   SB-4   Uncanonicalizeable state    → OxDeAIAuthorizationError, execute blocked
 *   SB-5   Determinism                 → same state always produces the same hash
 *   SB-6   TOCTOU state mutation       → state mutated after auth issued → execute blocked
 *   SB-7   Null execution state        → computeStateHash throws → execute blocked
 *   SB-8   Boundary integrity          → mismatch blocks beforeExecute, execute, and setState
 *   SB-9   Pluggable computeStateHash  → matching custom strategy → execute runs
 *   SB-10  Pluggable computeStateHash  → hash mismatch → execute blocked
 *   SB-11  Compatible hash strategy    → provider hash committed + verified consistently → execute runs
 *   SB-12  Incompatible hash strategy  → ambiguous config → execute blocked (fail-closed)
 *   SB-13  computeStateHash throws     → OxDeAIAuthorizationError, execute blocked (fail-closed)
 */

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import type { Authorization, Intent, State } from "@oxdeai/core";
import { stateSnapshotHash, intentHash } from "@oxdeai/core";

import { OxDeAIGuard } from "../guard.js";
import { OxDeAIAuthorizationError } from "../errors.js";
import { TEST_KEYSET, signAuth } from "./helpers/fixtures.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import type { OxDeAIGuardConfig, ProposedAction } from "../types.js";

// ── shared fixtures ────────────────────────────────────────────────────────────

// Fixed fields ensure defaultNormalizeAction is deterministic across calls.
const ACTION: ProposedAction = {
  name: "transfer",
  args: { amount: 100 },
  estimatedCost: 0,
  timestampSeconds: 1_700_000_000,
  context: { agent_id: "agent-sb", intent_id: "sb-fixed-intent-id", nonce: 1n },
};
// Pre-compute once so all signAuth calls can embed the correct intent_hash.
const FIXED_INTENT_HASH = intentHash(defaultNormalizeAction(ACTION));

function makeBaseState(): State {
  return {
    policy_version: "sb-policy",
    period_id: "sb-p1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit: { "agent-sb": 1_000_000n },
      spent_in_period: { "agent-sb": 0n },
    },
    max_amount_per_action: { "agent-sb": 1_000_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-sb": 10 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-sb": 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { "agent-sb": 100 }, calls: {} },
  };
}

function makeFakeEngine(auth: ReturnType<typeof signAuth>, _state: State) {
  return {
    evaluatePure(_intent: Intent, s: State) {
      return {
        decision: "ALLOW" as const,
        reasons: [],
        authorization: auth as unknown as Authorization,
        nextState: s,
      };
    },
    computeStateHash: (s: State) => stateSnapshotHash(s),
  };
}

function makeGuardConfig(
  auth: ReturnType<typeof signAuth>,
  state: State,
  overrides?: Partial<OxDeAIGuardConfig>
): OxDeAIGuardConfig {
  let stored = state;
  let storedVersion = 0;
  return {
    engine: makeFakeEngine(auth, state) as any,
    getState: async () => ({ state: stored, version: storedVersion }),
    setState: async (s, v) => { if (v !== storedVersion) return false; stored = s; storedVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    ...overrides,
  };
}

// ── SB-1: Matching state_hash → execute runs ───────────────────────────────────

test("SB-1 matching state_hash: execute runs and result is returned", async () => {
  const state = makeBaseState();
  const auth = signAuth({
    auth_id: "sb1-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(state),
    intent_hash: FIXED_INTENT_HASH,
  });

  const guard = OxDeAIGuard(makeGuardConfig(auth, state));
  let executed = false;
  const result = await guard(ACTION, async () => { executed = true; return "sb1-ok"; });

  assert.ok(executed, "execute must be called when state_hash matches");
  assert.equal(result, "sb1-ok");
});

// ── SB-2: Mismatched state_hash → execute blocked ─────────────────────────────

test("SB-2 mismatched state_hash: execute is blocked and OxDeAIAuthorizationError is thrown", async () => {
  const state = makeBaseState();
  // Auth commits to a different state (wrong hash).
  const wrongHash = "a".repeat(64);
  const auth = signAuth({
    auth_id: "sb2-auth",
    audience: "aud-test",
    state_hash: wrongHash,
    intent_hash: FIXED_INTENT_HASH,
  });

  const guard = OxDeAIGuard(makeGuardConfig(auth, state));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`);
      assert.ok(
        err.message.includes("state_hash"),
        `error message should mention state_hash, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when state_hash does not match");
});

// ── SB-3: Empty state_hash → execute blocked ──────────────────────────────────

test("SB-3 empty state_hash in authorization: execute is blocked and OxDeAIAuthorizationError is thrown", async () => {
  const state = makeBaseState();
  // signAuth defaults state_hash to "s".repeat(64); override to empty string.
  // verifyAuthorization (strict) rejects empty state_hash before state binding.
  const auth = signAuth({
    auth_id: "sb3-auth",
    audience: "aud-test",
    state_hash: "",
  });

  const guard = OxDeAIGuard(makeGuardConfig(auth, state));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when state_hash is empty");
});

// ── SB-4: Uncanonicalizeable state → execute blocked ──────────────────────────

test("SB-4 state that cannot be canonicalized: execute is blocked and OxDeAIAuthorizationError is thrown", async () => {
  const state = makeBaseState();
  const auth = signAuth({
    auth_id: "sb4-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(state),
    intent_hash: FIXED_INTENT_HASH,
  });

  // Introduce a circular reference so JSON.stringify throws inside stateSnapshotHash.
  const circularState = { ...state } as any;
  circularState._self = circularState;

  const guard = OxDeAIGuard(makeGuardConfig(auth, circularState));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`);
      assert.ok(
        err.message.includes("canonicalization") || err.message.includes("state_hash"),
        `error message should indicate canonicalization or state_hash failure, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when state cannot be canonicalized");
});

// ── SB-5: Determinism — same state always produces the same hash ───────────────

test("SB-5 determinism: stateSnapshotHash is stable and three guard runs with the same state all ALLOW", async () => {
  const state = makeBaseState();

  // Hash stability: repeated calls on the same state object return the same value.
  const h1 = stateSnapshotHash(state);
  const h2 = stateSnapshotHash(state);
  const h3 = stateSnapshotHash(state);
  assert.equal(h1, h2, "stateSnapshotHash must be idempotent (call 1 vs 2)");
  assert.equal(h2, h3, "stateSnapshotHash must be idempotent (call 2 vs 3)");

  // Structural equivalence: two independent makeBaseState() calls hash the same.
  const state2 = makeBaseState();
  assert.equal(
    stateSnapshotHash(state),
    stateSnapshotHash(state2),
    "two independent makeBaseState() objects must hash identically"
  );

  // structuredClone stability: a deep clone produces the same hash.
  const cloned = structuredClone(state);
  assert.equal(
    stateSnapshotHash(state),
    stateSnapshotHash(cloned),
    "structuredClone of state must hash identically to the original"
  );

  // Three independent guard runs, each with a distinct auth_id but the same
  // state_hash commitment, all produce ALLOW.
  const sharedHash = stateSnapshotHash(state);
  for (const [idx, authId] of (["sb5-run-a", "sb5-run-b", "sb5-run-c"] as const).entries()) {
    const auth = signAuth({ auth_id: authId, audience: "aud-test", state_hash: sharedHash, intent_hash: FIXED_INTENT_HASH });
    const guard = OxDeAIGuard(makeGuardConfig(auth, makeBaseState()));
    let ran = false;
    const res = await guard(ACTION, async () => { ran = true; return `run-${idx}`; });
    assert.ok(ran, `run ${authId}: execute must be called`);
    assert.equal(res, `run-${idx}`, `run ${authId}: result must be returned`);
  }
});

// ── SB-6: TOCTOU — state mutated after auth was issued → execute blocked ───────

test("SB-6 TOCTOU state mutation: state modified after authorization was issued blocks execution", async () => {
  // Auth was issued against a clean state (spent_in_period: 0n).
  const authState = makeBaseState();
  const auth = signAuth({
    auth_id: "sb6-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(authState),
    intent_hash: FIXED_INTENT_HASH,
  });

  // By execution time, state has advanced (a payment was recorded).
  const executionState = makeBaseState();
  executionState.budget.spent_in_period["agent-sb"] = 500_000n;

  // stateSnapshotHash must differ between authState and executionState.
  assert.notEqual(
    stateSnapshotHash(authState),
    stateSnapshotHash(executionState),
    "precondition: authState and executionState must have different hashes"
  );

  const guard = OxDeAIGuard(makeGuardConfig(auth, executionState));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(
        err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`
      );
      assert.ok(
        err.message.includes("state_hash"),
        `error message should mention state_hash, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when state was mutated after auth was issued");
});

// ── SB-7: Null execution state → computeStateHash throws → execute blocked ─────

test("SB-7 null execution state: computeStateHash throws and execution is blocked", async () => {
  // Build an auth with a valid, non-empty state_hash so it passes strictVerifyAuthorization.
  const validState = makeBaseState();
  const auth = signAuth({
    auth_id: "sb7-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(validState),
    intent_hash: FIXED_INTENT_HASH,
  });

  // Custom engine whose computeStateHash explicitly throws for null/undefined state.
  // evaluatePure returns ALLOW+nextState even when given null so the guard reaches step 6c.
  const nullSafeNextState = makeBaseState();
  const engineWithNullGuard = {
    evaluatePure(_intent: Intent, _s: unknown) {
      return {
        decision: "ALLOW" as const,
        reasons: [],
        authorization: auth as unknown as Authorization,
        nextState: nullSafeNextState,
      };
    },
    computeStateHash(s: unknown): string {
      if (s === null || s === undefined) {
        throw new TypeError("computeStateHash: state is null or undefined");
      }
      return stateSnapshotHash(s as State);
    },
  };

  const config: OxDeAIGuardConfig = {
    engine: engineWithNullGuard as any,
    // getState returns null state — simulates a broken/uninitialized state store.
    getState: async () => ({ state: null as unknown as State, version: 0 }),
    setState: async () => true,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(
        err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`
      );
      assert.ok(
        err.message.includes("canonicalization") || err.message.includes("State"),
        `error message should indicate state failure, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when state is null");
});

// ── SB-8: Boundary integrity — mismatch blocks beforeExecute, execute, setState ─

test("SB-8 boundary integrity: state_hash mismatch blocks beforeExecute, execute, and setState", async () => {
  // Auth commits to a clean state; guard will see a mutated state at execution time.
  const authState = makeBaseState();
  const auth = signAuth({
    auth_id: "sb8-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(authState),
    intent_hash: FIXED_INTENT_HASH,
  });

  const executionState = makeBaseState();
  executionState.budget.spent_in_period["agent-sb"] = 999_999n;

  let beforeExecuteCalled = false;
  let setStateCalled = false;
  let executeCalled = false;

  const config = makeGuardConfig(auth, executionState, {
    beforeExecute: async () => { beforeExecuteCalled = true; },
    setState: async () => { setStateCalled = true; return true; },
  });

  const guard = OxDeAIGuard(config);

  await assert.rejects(
    () => guard(ACTION, async () => { executeCalled = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError, "must throw OxDeAIAuthorizationError");
      return true;
    }
  );

  assert.ok(!beforeExecuteCalled, "beforeExecute must not be called when state_hash mismatches");
  assert.ok(!executeCalled, "execute must not be called when state_hash mismatches");
  assert.ok(!setStateCalled, "setState must not be called when state_hash mismatches");
});

// ── SB-9 through SB-12: Pluggable computeStateHash strategy ───────────────────
//
// These tests verify the config.computeStateHash option, which allows
// injecting a custom state hash function when authorizations are produced by
// an external provider with a different state canonicalization algorithm
// (e.g., Sift adapter: siftCanonicalJsonHash vs Core: stateSnapshotHash).

// Simulates a provider-specific state hash algorithm (e.g., siftCanonicalJsonHash).
// Deterministic, but distinct from stateSnapshotHash for any state.
function providerSpecificHash(_state: unknown): string {
  return createHash("sha256").update("provider-specific-state-repr").digest("hex");
}

// ── SB-9: Pluggable computeStateHash with matching commitment → execute runs ───

test("SB-9 pluggable computeStateHash: matching hash commitment with custom strategy → execute runs", async () => {
  const state = makeBaseState();
  // Auth committed with provider-specific hash (not stateSnapshotHash).
  const auth = signAuth({
    auth_id: "sb9-auth",
    audience: "aud-test",
    state_hash: providerSpecificHash(state),
    intent_hash: FIXED_INTENT_HASH,
  });

  // Guard configured with the matching custom computeStateHash.
  const guard = OxDeAIGuard(makeGuardConfig(auth, state, {
    computeStateHash: providerSpecificHash,
  }));
  let executed = false;
  const result = await guard(ACTION, async () => { executed = true; return "sb9-ok"; });

  assert.ok(executed, "execute must be called when computeStateHash matches the commitment");
  assert.equal(result, "sb9-ok");
});

// ── SB-10: Pluggable computeStateHash with mismatched hash → execute blocked ───

test("SB-10 pluggable computeStateHash: hash mismatch blocks execution", async () => {
  const state = makeBaseState();
  // Auth committed with provider-specific hash.
  const auth = signAuth({
    auth_id: "sb10-auth",
    audience: "aud-test",
    state_hash: providerSpecificHash(state),
    intent_hash: FIXED_INTENT_HASH,
  });

  // Guard configured with a DIFFERENT strategy than was used at signing time.
  // This simulates using the wrong computeStateHash — incompatible config.
  const guard = OxDeAIGuard(makeGuardConfig(auth, state, {
    computeStateHash: (s) => stateSnapshotHash(s),
  }));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`);
      assert.ok(
        err.message.includes("state_hash"),
        `error must mention state_hash, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when hash strategies are incompatible");
});

// ── SB-11: Provider-specific strategy used consistently → execute runs ─────────

test("SB-11 compatible hash strategy: provider-specific hash committed and verified with same strategy → execute runs", async () => {
  const state = makeBaseState();

  // Precondition: provider hash differs from Core default to ensure the
  // test is meaningful (not accidentally testing the same algorithm).
  assert.notEqual(
    providerSpecificHash(state),
    stateSnapshotHash(state),
    "precondition: provider hash must differ from Core stateSnapshotHash"
  );

  // Auth committed with provider-specific hash.
  const auth = signAuth({
    auth_id: "sb11-auth",
    audience: "aud-test",
    state_hash: providerSpecificHash(state),
    intent_hash: FIXED_INTENT_HASH,
  });

  // Guard correctly configured with the matching provider strategy.
  const guard = OxDeAIGuard(makeGuardConfig(auth, state, {
    computeStateHash: providerSpecificHash,
  }));
  let executed = false;
  const result = await guard(ACTION, async () => { executed = true; return "sb11-ok"; });

  assert.ok(executed, "execute must be called when provider strategy is configured correctly");
  assert.equal(result, "sb11-ok");
});

// ── SB-12: Incompatible/unconfigured strategy → execute blocked ────────────────
//
// Documents the correct integration requirement: when using an external
// authorization provider with a non-Core state hash algorithm, omitting
// config.computeStateHash causes a deterministic state_hash mismatch.
// This is the "ambiguous config" case — fail-closed.

test("SB-12 incompatible hash strategy (ambiguous config): provider hash committed, Core engine default at verification → blocked", async () => {
  const state = makeBaseState();

  // Auth committed with provider-specific hash (simulates Sift adapter output).
  const auth = signAuth({
    auth_id: "sb12-auth",
    audience: "aud-test",
    state_hash: providerSpecificHash(state),
    intent_hash: FIXED_INTENT_HASH,
  });

  // Precondition: the two hash functions produce different values for this state.
  assert.notEqual(
    stateSnapshotHash(state),
    providerSpecificHash(state),
    "precondition: Core and provider hashes must differ for this test to be meaningful"
  );

  // Guard NOT configured with computeStateHash → uses engine.computeStateHash
  // (which is stateSnapshotHash). This will not match the committed provider hash.
  const guard = OxDeAIGuard(makeGuardConfig(auth, state));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(
        err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`
      );
      assert.ok(
        err.message.includes("state_hash"),
        `error message should mention state_hash, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(
    !executed,
    "execute must not be called when computeStateHash is not configured for a non-Core provider"
  );
});

// ── SB-13: computeStateHash throws → OxDeAIAuthorizationError, execute blocked ──
//
// When config.computeStateHash throws for any reason, the guard must wrap the
// exception in OxDeAIAuthorizationError and block execution — fail-closed.
// The error message must clearly indicate that state hash computation failed.

test("SB-13 custom computeStateHash throws: execution is blocked fail-closed (OxDeAIAuthorizationError)", async () => {
  const state = makeBaseState();
  const auth = signAuth({
    auth_id: "sb13-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(state),
    intent_hash: FIXED_INTENT_HASH,
  });

  // computeStateHash always throws — simulates a broken or unavailable hash implementation.
  const guard = OxDeAIGuard(makeGuardConfig(auth, state, {
    computeStateHash: (_s) => {
      throw new Error("hash backend unavailable");
    },
  }));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(
        err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`
      );
      assert.ok(
        err.message.includes("canonicalization") || err.message.includes("State"),
        `error message must indicate state hash computation failed, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when computeStateHash throws");
});
