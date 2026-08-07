import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import { makeIntent } from "../helpers/intent.js";
import { makeState } from "../helpers/state.js";

test("INV-1 Budget Safety denies when exceeded", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });

  const state = makeState({
    policy_version: "0.1.0",
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["t1"] },
    budget: { budget_limit: { "agent-1": 10_000_000n }, spent_in_period: { "agent-1": 2_000_000n } },
    max_amount_per_action: { "agent-1": 20_000_000n }
  });
  const intent = makeIntent({
    nonce: 1n,
    amount: 9_000_000n,
    asset: "USDC",
    target: "t1",
    timestamp: 1000
  });

  const out = engine.evaluatePure(intent, state, intent.timestamp);
  assert.equal(out.decision, "DENY");
  assert.ok(out.reasons.includes("BUDGET_EXCEEDED"));
});

test("INV-2 Per-action cap denies when exceeded", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });

  const state = makeState({
    policy_version: "0.1.0",
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["t1"] },
    budget: { budget_limit: { "agent-1": 100_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 5_000_000n }
  });
  const intent = makeIntent({
    nonce: 2n,
    amount: 6_000_000n,
    asset: "USDC",
    target: "t1",
    timestamp: 1000
  });

  const out = engine.evaluatePure(intent, state, intent.timestamp);
  assert.equal(out.decision, "DENY");
  assert.ok(out.reasons.includes("PER_ACTION_CAP_EXCEEDED"));
});

test("INV-1a Negative amount cannot authorize or decrease budget accounting", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
  const state = makeState({
    policy_version: "0.1.0",
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["t1"] },
    budget: { budget_limit: { "agent-1": 10_000_000n }, spent_in_period: { "agent-1": 2_000_000n } },
    max_amount_per_action: { "agent-1": 5_000_000n }
  });
  const before = structuredClone(state);

  const out = engine.evaluatePure(makeIntent({ amount: -1n, asset: "USDC", target: "t1", timestamp: 1000 }), state, 1000);

  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_AMOUNT_INVALID"] });
  assert.deepEqual(state, before);
});

test("INV-1b ALLOW budget transitions are monotonic, while RELEASE does not write budget", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
  const state = makeState({
    policy_version: "0.1.0",
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["t1"] },
    budget: { budget_limit: { "agent-1": 10_000_000n }, spent_in_period: { "agent-1": 2_000_000n } },
    max_amount_per_action: { "agent-1": 5_000_000n }
  });

  for (const [index, amount] of [0n, 1n, 1_000_000n].entries()) {
    const out = engine.evaluatePure(
      makeIntent({ intent_id: `monotonic-${index}`, nonce: BigInt(index + 10), amount, asset: "USDC", target: "t1", timestamp: 1000 }),
      state,
      1000
    );
    assert.equal(out.decision, "ALLOW");
    assert.ok(out.nextState.budget.spent_in_period["agent-1"]! >= state.budget.spent_in_period["agent-1"]!);
  }

  const releaseState = makeState({
    policy_version: "0.1.0",
    budget: { budget_limit: { "agent-1": 10_000_000n }, spent_in_period: { "agent-1": 2_000_000n } },
    concurrency: {
      max_concurrent: { "agent-1": 10 },
      active: { "agent-1": 1 },
      active_auths: { "agent-1": { "auth-to-release": { expires_at: 2000 } } }
    }
  });
  const released = engine.evaluatePure(
    makeIntent({ type: "RELEASE", authorization_id: "auth-to-release", amount: 0n, nonce: 20n, timestamp: 1000 }),
    releaseState,
    1000
  );
  assert.equal(released.decision, "ALLOW");
  assert.equal(released.nextState.budget.spent_in_period["agent-1"], 2_000_000n);
});
