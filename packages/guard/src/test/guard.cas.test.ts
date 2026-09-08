// SPDX-License-Identifier: Apache-2.0
/**
 * guard.cas.test.ts
 *
 * Regression tests for the compare-and-set (CAS) state persistence protocol
 * at the reusable PEP boundary (issue #36).
 *
 * Protocol requirements:
 *   - getState() returns { state, version }
 *   - setState(nextState, expectedVersion) returns true on success,
 *     false on version mismatch (concurrent modification)
 *   - The guard throws OxDeAIConflictError and blocks execution on false
 *   - The CAS commit happens BEFORE execute() — a mismatch has no side effects
 *   - Missing version from the store is fail-closed (OxDeAIAuthorizationError)
 *
 * Test IDs: CAS-1 through CAS-6.
 *
 *   CAS-1  Matching version → execution allowed, setState called with correct version
 *   CAS-2  Concurrent write advances version between read and commit → OxDeAIConflictError, execute not called
 *   CAS-3  Concurrent double-execution simulation → second call denied via CAS
 *   CAS-4  Missing version from store → OxDeAIAuthorizationError (fail-closed)
 *   CAS-5  CAS failure: engine's nextState not committed, beforeExecute and execute never called
 *   CAS-6  Determinism: identical inputs produce identical outcomes across independent guard instances
 */

import test from "node:test";
import assert from "node:assert/strict";

import type { Authorization, Intent, State } from "@oxdeai/core";
import { stateSnapshotHash, intentHash } from "@oxdeai/core";

import { OxDeAIGuard } from "../guard.js";
import {
  OxDeAIAuthorizationError,
  OxDeAIConflictError,
} from "../errors.js";
import { TEST_KEYSET, signAuth } from "./helpers/fixtures.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import type { OxDeAIGuardConfig, ProposedAction, StateVersion } from "../types.js";

// ── Fixtures ───────────────────────────────────────────────────────────────────

// Fixed fields make defaultNormalizeAction deterministic so the intent_hash
// can be pre-computed and embedded in every signAuth call that needs to reach
// the CAS step or succeed.
const ACTION: ProposedAction = {
  name: "transfer",
  args: { amount: 100 },
  estimatedCost: 0,
  timestampSeconds: 1_700_000_000,
  context: { agent_id: "agent-cas", intent_id: "cas-fixed-intent-id", nonce: 1n },
};
const FIXED_INTENT_HASH = intentHash(defaultNormalizeAction(ACTION));

function makeBaseState(): State {
  return {
    policy_version: "cas-policy",
    period_id: "cas-p1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit: { "agent-cas": 1_000_000n },
      spent_in_period: { "agent-cas": 0n },
    },
    max_amount_per_action: { "agent-cas": 1_000_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-cas": 10 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-cas": 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { "agent-cas": 100 }, calls: {} },
  };
}

function makeFakeEngine(auth: ReturnType<typeof signAuth>) {
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

/**
 * Build a CAS-aware state store.
 * Returns { getState, setState } ready to spread into OxDeAIGuardConfig,
 * plus helpers for inspecting and manipulating the store in tests.
 */
function makeCasStore(initial: State, startVersion: StateVersion = 0): {
  getState: () => { state: State; version: StateVersion };
  setState: (s: State, v: StateVersion) => boolean;
  forceVersion: (v: StateVersion) => void;
  currentVersion: () => StateVersion;
  currentState: () => State;
} {
  let stored = initial;
  let version: StateVersion = startVersion;
  return {
    getState: () => ({ state: stored, version }),
    setState: (s, v) => {
      if (v !== version) return false;
      stored = s;
      version = typeof version === "number"
        ? version + 1
        : `${parseInt(String(version), 10) + 1}`;
      return true;
    },
    forceVersion: (v) => { version = v; },
    currentVersion: () => version,
    currentState: () => stored,
  };
}

// ── CAS-1: Matching version → execution allowed ────────────────────────────────

test("CAS-1 matching version: execution allowed and setState is called with the version read by getState", async () => {
  const state = makeBaseState();
  const auth = signAuth({
    auth_id: "cas1-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(state),
    intent_hash: FIXED_INTENT_HASH,
  });

  const store = makeCasStore(state, 0);
  let setStateCalled = false;
  let capturedVersion: StateVersion | undefined;

  const config: OxDeAIGuardConfig = {
    engine: makeFakeEngine(auth) as any,
    getState: store.getState,
    setState: (s, v) => {
      setStateCalled = true;
      capturedVersion = v;
      return store.setState(s, v);
    },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);
  let executed = false;
  await guard(ACTION, async () => { executed = true; });

  assert.ok(executed, "execute must be called when version matches");
  assert.ok(setStateCalled, "setState must be called on ALLOW");
  assert.equal(capturedVersion, 0, "setState must receive the version that getState returned");
  assert.equal(store.currentVersion(), 1, "version must be incremented after successful setState");
});

// ── CAS-2: Concurrent write advances version → OxDeAIConflictError ─────────────
//
// Story: guard reads version 0, a concurrent writer advances the store to
// version 1 before the guard's setState reaches the store. The guard's
// CAS attempt with stale version 0 is rejected.

test("CAS-2 concurrent write advances version before commit: OxDeAIConflictError thrown, execute never called", async () => {
  const state = makeBaseState();
  const auth = signAuth({
    auth_id: "cas2-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(state),
    intent_hash: FIXED_INTENT_HASH,
  });

  const store = makeCasStore(state, 0);
  let setStateAttempted = false;

  const config: OxDeAIGuardConfig = {
    engine: makeFakeEngine(auth) as any,
    // getState returns version 0 — the version the guard will evaluate against.
    getState: store.getState,
    setState: (s, v) => {
      setStateAttempted = true;
      // Simulate: a concurrent writer commits between the guard's getState()
      // and setState() calls, advancing the stored version from 0 to 1.
      store.forceVersion(1);
      // Guard presents version 0; stored version is now 1 → mismatch → false.
      return store.setState(s, v);
    },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(
        err instanceof OxDeAIConflictError,
        `expected OxDeAIConflictError, got: ${Object.prototype.toString.call(err)}`
      );
      assert.ok(
        err.message.includes("version mismatch") || err.message.includes("concurrent"),
        `message must indicate version conflict, got: "${err.message}"`
      );
      return true;
    }
  );

  assert.ok(!executed, "execute must not be called when concurrent write advanced the version");
  assert.ok(setStateAttempted, "setState must have been attempted (CAS was reached before execute)");
  // The store is at version 1 (the concurrent writer's version), not 2.
  // The guard's proposed commit did not advance the version.
  assert.equal(store.currentVersion(), 1,
    "store version must reflect the concurrent write only — guard's stale commit must not have advanced it");
});

// ── CAS-3: Concurrent double-execution → second call denied via CAS ────────────

test("CAS-3 concurrent double-execution: second guard call is denied when version has advanced", async () => {
  // Simulate two guard calls racing on the same state.
  // Both evaluate policy against version 0. The first call commits (version → 1).
  // The second call then tries to CAS with stale version 0 → fails.
  const state = makeBaseState();
  const stateHash = stateSnapshotHash(state);

  // Two separate auth_ids so replay detection doesn't interfere.
  const auth1 = signAuth({ auth_id: "cas3-auth-a", audience: "aud-test", state_hash: stateHash, intent_hash: FIXED_INTENT_HASH });
  const auth2 = signAuth({ auth_id: "cas3-auth-b", audience: "aud-test", state_hash: stateHash, intent_hash: FIXED_INTENT_HASH });

  const store = makeCasStore(state, 0);

  let callIndex = 0;
  // The engine alternates auths so each guard call gets a unique auth_id.
  const engine = {
    evaluatePure(_intent: Intent, s: State) {
      const auth = callIndex++ === 0 ? auth1 : auth2;
      return {
        decision: "ALLOW" as const,
        reasons: [],
        authorization: auth as unknown as Authorization,
        nextState: s,
      };
    },
    computeStateHash: (s: State) => stateSnapshotHash(s),
  };

  const config: OxDeAIGuardConfig = {
    engine: engine as any,
    getState: store.getState,
    setState: store.setState,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);

  // First call: succeeds, version advances to 1.
  let firstExecuted = false;
  await guard(ACTION, async () => { firstExecuted = true; });
  assert.ok(firstExecuted, "first call must execute");
  assert.equal(store.currentVersion(), 1, "version must be 1 after first call");

  // Simulate stale read: a "concurrent" guard call that evaluated state at version 0.
  // Achieved by making getState return version 0 while the real store is at version 1.
  const staleConfig: OxDeAIGuardConfig = {
    engine: engine as any,
    // Frozen snapshot at version 0 — simulates a concurrent request that read state
    // before the first call committed.
    getState: () => ({ state, version: 0 }),
    setState: store.setState, // shared store that will reject the stale version
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const staleGuard = OxDeAIGuard(staleConfig);
  let secondExecuted = false;

  await assert.rejects(
    () => staleGuard(ACTION, async () => { secondExecuted = true; }),
    (err: unknown) => {
      assert.ok(
        err instanceof OxDeAIConflictError,
        `expected OxDeAIConflictError on stale CAS, got: ${Object.prototype.toString.call(err)}`
      );
      return true;
    }
  );

  assert.ok(!secondExecuted, "second (stale) call must not execute");
  assert.equal(store.currentVersion(), 1,
    "version must remain 1 — stale CAS must not commit or advance the version");
});

// ── CAS-4: Missing version from store → OxDeAIAuthorizationError ──────────────

test("CAS-4 missing version from store: OxDeAIAuthorizationError thrown (fail-closed)", async () => {
  const state = makeBaseState();
  const auth = signAuth({ auth_id: "cas4-auth", audience: "aud-test" });

  const config: OxDeAIGuardConfig = {
    engine: makeFakeEngine(auth) as any,
    // Return undefined version — simulates a misconfigured or legacy store.
    getState: () => ({ state, version: undefined as unknown as number }),
    setState: () => true,
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
      // Must NOT be OxDeAIConflictError — missing version is a config error, not a race.
      assert.ok(
        !(err instanceof OxDeAIConflictError),
        "missing version must throw OxDeAIAuthorizationError, not OxDeAIConflictError"
      );
      assert.ok(
        err.message.includes("version") || err.message.includes("CAS"),
        `message must indicate missing version, got: "${err.message}"`
      );
      return true;
    }
  );

  assert.ok(!executed, "execute must not be called when version is missing");
});

// ── CAS-5: CAS failure — no side effects, proposed nextState not committed ─────
//
// Guards three invariants simultaneously:
//   (a) beforeExecute hook is not invoked
//   (b) execute callback is not invoked
//   (c) the engine's proposed nextState is NOT written to the store
//
// Uses a distinctly modified nextState (period_id changed) so invariant (c)
// is independently verifiable via store.currentState().

test("CAS-5 CAS failure: engine's nextState not committed, beforeExecute and execute never called", async () => {
  const state = makeBaseState();
  const stateHash = stateSnapshotHash(state);
  const auth = signAuth({ auth_id: "cas5-auth", audience: "aud-test", state_hash: stateHash, intent_hash: FIXED_INTENT_HASH });

  const store = makeCasStore(state, 0);
  let beforeExecuteCalled = false;
  let executeCalled = false;

  // Engine returns a structurally distinct nextState so we can verify it was not committed.
  // state_hash in auth is computed from the current state — the binding check passes.
  // The modified nextState is only relevant at commit time.
  const engine = {
    evaluatePure(_intent: Intent, s: State) {
      const nextState: State = { ...s, period_id: "modified-by-engine" };
      return {
        decision: "ALLOW" as const,
        reasons: [],
        authorization: auth as unknown as Authorization,
        nextState,
      };
    },
    computeStateHash: (s: State) => stateSnapshotHash(s),
  };

  const config: OxDeAIGuardConfig = {
    engine: engine as any,
    getState: store.getState,   // returns version 0
    setState: (s, v) => {
      // Simulate concurrent write advancing the version before this guard commits.
      store.forceVersion(1);
      return store.setState(s, v); // v=0 !== stored=1 → false
    },
    beforeExecute: async () => { beforeExecuteCalled = true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);

  await assert.rejects(
    () => guard(ACTION, async () => { executeCalled = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIConflictError,
        "must throw OxDeAIConflictError on CAS failure");
      return true;
    }
  );

  // (a) beforeExecute must not run
  assert.ok(!beforeExecuteCalled,
    "beforeExecute must NOT be called when CAS setState fails");

  // (b) execute must not run
  assert.ok(!executeCalled,
    "execute must NOT be called when CAS setState fails");

  // (c) the engine's modified nextState must not have been written to the store
  assert.equal(store.currentState().period_id, state.period_id,
    "store must still hold the original state — engine's nextState must not have been committed");

  // Version reflects only the simulated concurrent write, not a guard-initiated commit.
  assert.equal(store.currentVersion(), 1,
    "version must reflect the concurrent write (1), not a successful guard commit");
});

// ── CAS-6: Determinism ─────────────────────────────────────────────────────────
//
// Given identical input state, version, and authorization shape, independent
// guard instances must produce identical outcomes. Proves there is no hidden
// mutable state in the guard factory that makes results non-deterministic.
//
// Each run uses a fresh guard instance (own replay store) and structurally
// identical state + version. The same auth_id is legal here because each
// guard has its own in-memory replay store.

test("CAS-6 determinism: identical inputs produce identical outcomes across independent guard instances", async () => {
  const RUNS = 5;

  // All runs start from a structurally identical state at version 0.
  // The auth state_hash is computed from this canonical state.
  const canonicalState = makeBaseState();
  const canonicalStateHash = stateSnapshotHash(canonicalState);

  // Same auth shape on every run — deterministic because Ed25519 signing is
  // deterministic (RFC 8032) and all inputs are identical.
  const auth = signAuth({
    auth_id: "cas6-auth",
    audience: "aud-test",
    state_hash: canonicalStateHash,
    intent_hash: FIXED_INTENT_HASH,
  });

  const engine = makeFakeEngine(auth);

  type RunOutcome = {
    executed: boolean;
    result: unknown;
    setStateCalledWith: StateVersion;
    versionAfterCommit: StateVersion;
  };

  const outcomes: RunOutcome[] = [];

  for (let i = 0; i < RUNS; i++) {
    // Fresh store and guard instance each run — no shared state between runs.
    const store = makeCasStore(makeBaseState(), 0);
    let capturedVersion: StateVersion | undefined;

    const config: OxDeAIGuardConfig = {
      engine: engine as any,
      getState: store.getState,
      setState: (s, v) => {
        capturedVersion = v;
        return store.setState(s, v);
      },
      trustedKeySets: [TEST_KEYSET],
      expectedAudience: "aud-test",
    };

    const guard = OxDeAIGuard(config);
    let executed = false;
    const result = await guard(ACTION, async () => {
      executed = true;
      return "ok";
    });

    outcomes.push({
      executed,
      result,
      setStateCalledWith: capturedVersion!,
      versionAfterCommit: store.currentVersion(),
    });
  }

  // Each run must individually satisfy the expected outcome.
  for (let i = 0; i < RUNS; i++) {
    const o = outcomes[i];
    assert.ok(o.executed,
      `run ${i}: execute must be called on ALLOW`);
    assert.equal(o.result, "ok",
      `run ${i}: result must be "ok"`);
    assert.equal(o.setStateCalledWith, 0,
      `run ${i}: setState must be called with the version read by getState (0)`);
    assert.equal(o.versionAfterCommit, 1,
      `run ${i}: store version must advance to 1 after successful commit`);
  }

  // All runs must produce structurally identical outcomes — guard is deterministic.
  const reference = outcomes[0];
  for (let i = 1; i < RUNS; i++) {
    assert.deepEqual(outcomes[i], reference,
      `run ${i} must produce an identical outcome to run 0`);
  }
});
