// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { BudgetModule } from "../policy/modules/BudgetModule.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import type { Intent } from "../types/intent.js";
import { ReasonCode as ReasonCodeValues } from "../types/policy.js";
import type { ReasonCode } from "../types/policy.js";
import type { State } from "../types/state.js";

const AGENT = "agent-1";
const NOW = 1_000_000;

function engine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1-negative-amount",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
}

function state(spent = 900n): State {
  return {
    policy_version: "v1-negative-amount",
    period_id: "period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant"] },
    budget: { budget_limit: { [AGENT]: 2_000n }, spent_in_period: { [AGENT]: spent } },
    max_amount_per_action: { [AGENT]: 1_000n },
    velocity: { config: { window_seconds: 60, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3_600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { [AGENT]: 100 }, active: {}, active_auths: {} },
    recursion: { max_depth: { [AGENT]: 10 } },
    tool_limits: { window_seconds: 60, max_calls: { [AGENT]: 100 }, calls: {} }
  };
}

function intent(amount: bigint, nonce = 1n): Intent {
  return {
    intent_id: `negative-amount-${nonce}`,
    agent_id: AGENT,
    action_type: "PAYMENT",
    type: "EXECUTE",
    amount,
    asset: "USDC",
    target: "merchant",
    timestamp: NOW,
    metadata_hash: "0".repeat(64),
    nonce,
    signature: "sig",
    depth: 0
  };
}

test("evaluatePure denies a negative amount before authorization or state transition", () => {
  const inputState = state();
  const before = structuredClone(inputState);

  const out = engine().evaluatePure(intent(-100_000n), inputState, NOW);

  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_AMOUNT_INVALID"] });
  assert.equal("authorization" in out, false);
  assert.equal("nextState" in out, false);
  assert.deepEqual(inputState, before);
  assert.equal(inputState.budget.spent_in_period[AGENT], 900n);
});

test("evaluate denies a negative amount without mutating spent_in_period", () => {
  const inputState = state();
  const before = structuredClone(inputState);

  const out = engine().evaluate(intent(-100_000n), inputState, NOW);

  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_AMOUNT_INVALID"] });
  assert.equal("authorization" in out, false);
  assert.deepEqual(inputState, before);
  assert.equal(inputState.budget.spent_in_period[AGENT], 900n);
});

test("negative amount is invalid for RELEASE before release modules run", () => {
  const release = {
    ...intent(-1n, 2n),
    type: "RELEASE" as const,
    authorization_id: "auth-to-release"
  };

  const out = engine().evaluatePure(release, state(), NOW);

  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_AMOUNT_INVALID"] });
});

test("zero and positive amounts preserve budget behavior", () => {
  const zero = engine().evaluatePure(intent(0n, 2n), state(), NOW);
  assert.equal(zero.decision, "ALLOW");
  assert.equal(zero.nextState.budget.spent_in_period[AGENT], 900n);

  const positive = engine().evaluatePure(intent(50n, 3n), state(), NOW);
  assert.equal(positive.decision, "ALLOW");
  assert.equal(positive.nextState.budget.spent_in_period[AGENT], 950n);
});

test("existing per-action and period budget limits still deny normally", () => {
  const cap = engine().evaluatePure(intent(1_001n, 4n), state(), NOW);
  assert.equal(cap.decision, "DENY");
  assert.deepEqual(cap.reasons, ["PER_ACTION_CAP_EXCEEDED"]);

  const period = engine().evaluatePure(intent(101n, 5n), state(1_900n), NOW);
  assert.equal(period.decision, "DENY");
  assert.deepEqual(period.reasons, ["BUDGET_EXCEEDED"]);
});

test("BudgetModule independently denies a negative amount without a state delta", () => {
  const inputState = state();
  const before = structuredClone(inputState);

  const out = BudgetModule(intent(-1n), inputState);

  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_AMOUNT_INVALID"] });
  assert.equal("stateDelta" in out, false);
  assert.deepEqual(inputState, before);
});

test("INTENT_AMOUNT_INVALID is part of the public ReasonCode surface", () => {
  const reason: ReasonCode = "INTENT_AMOUNT_INVALID";
  assert.equal(ReasonCodeValues.INTENT_AMOUNT_INVALID, reason);
});
