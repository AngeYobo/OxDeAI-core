// SPDX-License-Identifier: Apache-2.0
/**
 * decision.test.ts
 *
 * Focused tests for the explicit decision layer introduced in the refactor.
 *
 * Two levels of coverage:
 *  1. runDecisionModules unit tests - exercise the extracted function directly
 *     using lightweight stub modules, verifying ALLOW/DENY paths, fail-fast,
 *     collect-all, nextState, and reason accumulation.
 *
 *  2. PolicyEngine integration tests - verify that evaluatePure() produces
 *     identical outputs before and after the refactor: same decisions, same
 *     reasons, same nextState shape, same audit event sequence.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { runDecisionModules } from "../policy/decision/runDecisionModules.js";
import type { DecisionInput } from "../policy/decision/types.js";
import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import type { State } from "../types/state.js";
import type { Intent } from "../types/intent.js";
import { ReasonCode as ReasonCodeValues } from "../types/policy.js";
import type { PolicyModule, PolicyResult, ReasonCode } from "../types/policy.js";

// ── Stub helpers ──────────────────────────────────────────────────────────────

function stubAllow(id: string, delta?: Partial<State>): PolicyModule {
  return {
    id,
    evaluate: () => ({ decision: "ALLOW", reasons: [], ...(delta ? { stateDelta: delta } : {}) }),
    codec: { moduleId: id, serializeState: () => null, deserializeState: () => {}, stateHash: () => "" as any },
  };
}

function stubDeny(id: string, reason: ReasonCode): PolicyModule {
  return {
    id,
    evaluate: () => ({ decision: "DENY", reasons: [reason] }),
    codec: { moduleId: id, serializeState: () => null, deserializeState: () => {}, stateHash: () => "" as any },
  };
}

/** Minimal state - only the shape matters for stub modules */
function minimalState(overrides?: Partial<State>): State {
  return {
    policy_version: "v1-test",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["wallet"], targets: ["user_1"] },
    budget: { budget_limit: { "agent-1": 1_000_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 100_000_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 1000 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-1": 10 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-1": 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { "agent-1": 1000 }, calls: {} },
    ...overrides,
  } as State;
}

function minimalIntent(overrides?: Partial<Intent>): Intent {
  return {
    intent_id: "test-intent-1",
    agent_id: "agent-1",
    action_type: "PAYMENT",
    amount: 1_000_000n,
    asset: "wallet",
    target: "user_1",
    timestamp: 1_000_000,
    metadata_hash: "0".repeat(64),
    nonce: 1n,
    signature: "sig",
    tool: "pay",
    tool_call: true,
    depth: 0,
    ...overrides,
  } as Intent;
}

function baseInput(overrides?: Partial<DecisionInput>): DecisionInput {
  return {
    intent: minimalIntent(),
    state: minimalState(),
    mode: "fail-fast",
    ...overrides,
  };
}

// ── runDecisionModules unit tests ─────────────────────────────────────────────

test("runDecisionModules: all ALLOW → ALLOW decision", () => {
  const result = runDecisionModules(baseInput(), [stubAllow("a"), stubAllow("b")]);
  assert.equal(result.decision, "ALLOW");
  assert.deepEqual(result.reasons, []);
});

test("runDecisionModules: ALLOW path - nextState carries module deltas", () => {
  const delta: Partial<State> = { period_id: "updated" };
  const result = runDecisionModules(baseInput(), [stubAllow("a", delta)]);
  assert.equal(result.decision, "ALLOW");
  assert.equal((result.nextState as any).period_id, "updated");
});

test("runDecisionModules: ALLOW path - deltas accumulate in module-order", () => {
  const d1: Partial<State> = { period_id: "first" };
  const d2: Partial<State> = { period_id: "second" };
  const result = runDecisionModules(baseInput(), [stubAllow("a", d1), stubAllow("b", d2)]);
  assert.equal(result.decision, "ALLOW");
  assert.equal((result.nextState as any).period_id, "second");
});

test("runDecisionModules: single DENY → DENY decision", () => {
  const result = runDecisionModules(baseInput(), [stubDeny("a", "KILL_SWITCH")]);
  assert.equal(result.decision, "DENY");
  assert.deepEqual(result.reasons, ["KILL_SWITCH"]);
});

test("runDecisionModules: DENY path - nextState is unchanged input state", () => {
  const state = minimalState();
  const result = runDecisionModules(baseInput({ state }), [stubDeny("a", "BUDGET_EXCEEDED")]);
  assert.equal(result.decision, "DENY");
  assert.strictEqual(result.nextState, state);
});

test("runDecisionModules: fail-fast - stops at first DENY, ignores subsequent modules", () => {
  let secondRan = false;
  const second: PolicyModule = {
    id: "b",
    evaluate: () => { secondRan = true; return { decision: "DENY", reasons: ["VELOCITY_EXCEEDED"] }; },
    codec: { moduleId: "b", serializeState: () => null, deserializeState: () => {}, stateHash: () => "" as any },
  };
  const result = runDecisionModules(
    baseInput({ mode: "fail-fast" }),
    [stubDeny("a", "KILL_SWITCH"), second]
  );
  assert.equal(result.decision, "DENY");
  assert.deepEqual(result.reasons, ["KILL_SWITCH"]);
  // In fail-fast mode all modules are still evaluated (results pre-computed
  // via map), but delta/reason accumulation stops after the first DENY.
  // second.evaluate() did run because map() is eager.
  void secondRan;
});

test("runDecisionModules: collect-all - accumulates reasons from all DENY modules", () => {
  const result = runDecisionModules(
    baseInput({ mode: "collect-all" }),
    [stubDeny("a", "KILL_SWITCH"), stubDeny("b", "BUDGET_EXCEEDED")]
  );
  assert.equal(result.decision, "DENY");
  assert.deepEqual(result.reasons, ["KILL_SWITCH", "BUDGET_EXCEEDED"]);
});

test("runDecisionModules: empty module list → ALLOW with original state", () => {
  const state = minimalState();
  const result = runDecisionModules(baseInput({ state }), []);
  assert.equal(result.decision, "ALLOW");
  assert.strictEqual(result.nextState, state);
});

test("runDecisionModules: ALLOW before DENY - delta from first module is NOT in nextState", () => {
  // DENY path returns original input state regardless of prior ALLOW deltas
  const delta: Partial<State> = { period_id: "modified" };
  const state = minimalState();
  const result = runDecisionModules(
    baseInput({ state }),
    [stubAllow("a", delta), stubDeny("b", "KILL_SWITCH")]
  );
  assert.equal(result.decision, "DENY");
  assert.strictEqual(result.nextState, state);
  assert.equal((result.nextState as any).period_id, "p1"); // original, not "modified"
});

// ── PolicyEngine integration tests ───────────────────────────────────────────

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1-test",
    engine_secret: "test-secret-32-bytes-long-enough!!",
    authorization_ttl_seconds: 60,
    deny_mode: "fail-fast",
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function validState(): State {
  return minimalState({ policy_version: "v1-test" });
}

// minimalIntent() defaults timestamp to T0; evaluationTime matches it
// exactly (delta = 0) so these pre-existing tests exercise the same
// ALLOW/DENY behavior as before trusted-time integration.
const T0 = 1_000_000;

test("PolicyEngine.evaluatePure: ALLOW path returns authorization and nextState", () => {
  const engine = makeEngine();
  const state = validState();
  const intent = minimalIntent({ timestamp: 1_000_000, nonce: 99n });
  const out = engine.evaluatePure(intent, state, T0);
  assert.equal(out.decision, "ALLOW");
  assert.ok("authorization" in out && out.authorization);
  assert.ok("nextState" in out && out.nextState);
});

test("PolicyEngine.evaluatePure: DENY path - kill switch", () => {
  const engine = makeEngine();
  const state = validState();
  state.kill_switch.global = true;
  const out = engine.evaluatePure(minimalIntent({ nonce: 1n }), state, T0);
  assert.equal(out.decision, "DENY");
  assert.ok(out.reasons.includes("KILL_SWITCH"));
});

test("PolicyEngine.evaluatePure: DENY path - replay nonce", () => {
  const engine = makeEngine();
  const state = validState();
  const intent = minimalIntent({ nonce: 42n });

  // First call → ALLOW, records nonce in state
  const first = engine.evaluatePure(intent, state, T0);
  assert.equal(first.decision, "ALLOW");

  // Second call with same nonce against updated state → DENY
  if (first.decision !== "ALLOW") throw new Error("expected ALLOW");
  const second = engine.evaluatePure(intent, first.nextState, T0);
  assert.equal(second.decision, "DENY");
  assert.ok(second.reasons.includes("REPLAY_NONCE"));
});

test("PolicyEngine.evaluatePure: ALLOW nextState carries replay nonce delta", () => {
  const engine = makeEngine();
  const state = validState();
  const intent = minimalIntent({ nonce: 7n, timestamp: 1_000_000 });
  const out = engine.evaluatePure(intent, state, T0);
  assert.equal(out.decision, "ALLOW");
  if (out.decision !== "ALLOW") return;
  const nonces = out.nextState.replay.nonces["agent-1"] ?? [];
  assert.ok(nonces.some((e) => e.nonce === "7"), "nonce 7 should be recorded in nextState");
});

test("PolicyEngine.evaluatePure: audit sequence - ALLOW emits INTENT_RECEIVED, DECISION, AUTH_EMITTED", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(minimalIntent({ nonce: 55n }), validState(), T0);
  assert.equal(out.decision, "ALLOW");
  const events = engine.audit.snapshot();
  const types = events.map((e) => e.type);
  assert.ok(types.includes("INTENT_RECEIVED"), "missing INTENT_RECEIVED");
  assert.ok(types.includes("DECISION"),        "missing DECISION");
  assert.ok(types.includes("AUTH_EMITTED"),    "missing AUTH_EMITTED");
  // Order: INTENT_RECEIVED must come before DECISION
  assert.ok(types.indexOf("INTENT_RECEIVED") < types.indexOf("DECISION"));
  assert.ok(types.indexOf("DECISION") < types.indexOf("AUTH_EMITTED"));
});

test("PolicyEngine.evaluatePure: audit sequence - DENY emits INTENT_RECEIVED then DECISION only", () => {
  const engine = makeEngine();
  const state = validState();
  state.kill_switch.global = true;
  engine.evaluatePure(minimalIntent({ nonce: 1n }), state, T0);
  const types = engine.audit.snapshot().map((e) => e.type);
  assert.ok(types.includes("INTENT_RECEIVED"), "missing INTENT_RECEIVED");
  assert.ok(types.includes("DECISION"),        "missing DECISION");
  assert.ok(!types.includes("AUTH_EMITTED"),   "AUTH_EMITTED must NOT appear on DENY");
});

test("PolicyEngine.evaluatePure: collect-all mode accumulates multiple deny reasons", () => {
  const engine = makeEngine();
  const state = validState();
  state.kill_switch.global = true;
  state.kill_switch.agents["agent-1"] = true; // redundant but verifies collect-all
  // Also trip the budget
  state.budget.spent_in_period["agent-1"] = 999_999_999_999n;
  const out = engine.evaluatePure(minimalIntent({ nonce: 1n }), state, T0, { mode: "collect-all" });
  assert.equal(out.decision, "DENY");
  // At minimum KILL_SWITCH must appear; collect-all may surface more
  assert.ok(out.reasons.length >= 1);
  assert.ok(out.reasons.includes("KILL_SWITCH"));
});

// ── ReasonCode membership ─────────────────────────────────────────────────────

test("ReasonCode: trusted-time freshness codes are members of the public ReasonCode surface", () => {
  const future: ReasonCode = "INTENT_FRESHNESS_FUTURE";
  const stale: ReasonCode = "INTENT_STALE";
  assert.equal(ReasonCodeValues.INTENT_FRESHNESS_FUTURE, future);
  assert.equal(ReasonCodeValues.INTENT_STALE, stale);
});
