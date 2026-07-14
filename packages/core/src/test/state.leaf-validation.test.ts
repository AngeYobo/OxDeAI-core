// SPDX-License-Identifier: Apache-2.0
/**
 * state.leaf-validation.test.ts
 *
 * Regression coverage for stateGuards.ts: corrupted per-agent or config
 * numeric leaves (wrong type, or NaN passing a bare `typeof === "number"`
 * check) must fail closed with STATE_INVALID rather than silently
 * mis-evaluating a budget/velocity/replay comparison.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import type { State } from "../types/state.js";
import type { Intent } from "../types/intent.js";

function validState(overrides?: Partial<State>): State {
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

function validIntent(overrides?: Partial<Intent>): Intent {
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

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1-test",
    engine_secret: "test-secret-32-bytes-long-enough!!",
    authorization_ttl_seconds: 60,
    deny_mode: "fail-fast",
  });
}

test("control: sound state returns ALLOW", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(validIntent(), validState());
  assert.equal(out.decision, "ALLOW");
});

test("corrupted budget.budget_limit as string returns DENY STATE_INVALID", () => {
  const engine = makeEngine();
  const state = validState();
  (state.budget.budget_limit as unknown as Record<string, unknown>)["agent-1"] = "1000";
  const out = engine.evaluatePure(validIntent(), state);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["STATE_INVALID"]);
});

test("corrupted budget.budget_limit / max_amount_per_action as NaN returns DENY STATE_INVALID", () => {
  const engine = makeEngine();

  const state1 = validState();
  (state1.budget.budget_limit as unknown as Record<string, unknown>)["agent-1"] = NaN;
  const out1 = engine.evaluatePure(validIntent(), state1);
  assert.equal(out1.decision, "DENY");
  assert.deepEqual(out1.reasons, ["STATE_INVALID"]);

  const state2 = validState();
  (state2.max_amount_per_action as unknown as Record<string, unknown>)["agent-1"] = NaN;
  const out2 = engine.evaluatePure(validIntent(), state2);
  assert.equal(out2.decision, "DENY");
  assert.deepEqual(out2.reasons, ["STATE_INVALID"]);
});

test("corrupted budget.spent_in_period as plain number returns DENY STATE_INVALID", () => {
  const engine = makeEngine();
  const state = validState();
  (state.budget.spent_in_period as unknown as Record<string, unknown>)["agent-1"] = 0;
  const out = engine.evaluatePure(validIntent(), state);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["STATE_INVALID"]);
});

test("corrupted velocity.config.window_seconds as NaN returns DENY STATE_INVALID", () => {
  const engine = makeEngine();
  const state = validState();
  state.velocity.config.window_seconds = NaN;
  const out = engine.evaluatePure(validIntent(), state);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["STATE_INVALID"]);
});

test("corrupted replay.window_seconds as NaN returns DENY STATE_INVALID", () => {
  const engine = makeEngine();
  const state = validState();
  state.replay.window_seconds = NaN;
  const out = engine.evaluatePure(validIntent(), state);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["STATE_INVALID"]);
});

test("control: kill_switch.agents[agent] = true returns DENY KILL_SWITCH", () => {
  const engine = makeEngine();
  const state = validState();
  state.kill_switch.agents["agent-1"] = true;
  const out = engine.evaluatePure(validIntent(), state);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["KILL_SWITCH"]);
});

test("control: kill_switch.agents[agent] = false allows evaluation to continue", () => {
  const engine = makeEngine();
  const state = validState();
  state.kill_switch.agents["agent-1"] = false;
  const out = engine.evaluatePure(validIntent(), state);
  assert.equal(out.decision, "ALLOW");
});

test("corrupted kill_switch.agents[agent] = 1 returns DENY STATE_INVALID", () => {
  const engine = makeEngine();
  const state = validState();
  (state.kill_switch.agents as unknown as Record<string, unknown>)["agent-1"] = 1;
  const out = engine.evaluatePure(validIntent(), state);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["STATE_INVALID"]);
});

test("corrupted kill_switch.agents[agent] = \"true\" returns DENY STATE_INVALID", () => {
  const engine = makeEngine();
  const state = validState();
  (state.kill_switch.agents as unknown as Record<string, unknown>)["agent-1"] = "true";
  const out = engine.evaluatePure(validIntent(), state);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["STATE_INVALID"]);
});

test("corrupted kill_switch.agents[agent] = {} returns DENY STATE_INVALID", () => {
  const engine = makeEngine();
  const state = validState();
  (state.kill_switch.agents as unknown as Record<string, unknown>)["agent-1"] = {};
  const out = engine.evaluatePure(validIntent(), state);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["STATE_INVALID"]);
});

test("corrupted kill_switch.agents container with a non-boolean element returns DENY STATE_INVALID", () => {
  const engine = makeEngine();
  const state = validState();
  (state.kill_switch as unknown as Record<string, unknown>)["agents"] = { "agent-1": true, "agent-2": null };
  const out = engine.evaluatePure(validIntent(), state);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["STATE_INVALID"]);
});
