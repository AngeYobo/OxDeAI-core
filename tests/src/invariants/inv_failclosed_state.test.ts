import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine } from "@oxdeai/core";
import type { Intent } from "@oxdeai/core";

test("INV-FailClosed: corrupted/incomplete state must DENY (never ALLOW)", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "failclosed-secret",
    authorization_ttl_seconds: 60
  });

  const now = 1000;

  const intent: Intent = {
    intent_id: "intent-failclosed",
    agent_id: "agent-A",
    action_type: "PAYMENT",
    amount: 1_000_000n,
    asset: "USDC",
    target: "merchant",
    timestamp: now,
    metadata_hash: "0x" + "0".repeat(64),
    nonce: 999n,
    signature: "sig"
  };

  // Case 1: state missing required fields (runtime corruption)
  const badState1: any = { policy_version: "0.1.0" };
  const out1 = engine.evaluate(intent, badState1);
  assert.equal(out1.decision, "DENY");

  // Case 2: missing budget_limit for agent => fail-closed STATE_INVALID
  const badState2: any = {
    policy_version: "0.1.0",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant"] },
    budget: { budget_limit: {}, spent_in_period: { "agent-A": 0n } },
    max_amount_per_action: { "agent-A": 5_000_000n },
    velocity: { config: { window_seconds: 60, max_actions: 10 }, counters: {} }
  };
  const out2 = engine.evaluate(intent, badState2);
  assert.equal(out2.decision, "DENY");
  assert.ok(out2.reasons.includes("STATE_INVALID"));

  // Case 3: missing per-action cap for agent => fail-closed STATE_INVALID
  const badState3: any = {
    policy_version: "0.1.0",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant"] },
    budget: { budget_limit: { "agent-A": 10_000_000n }, spent_in_period: { "agent-A": 0n } },
    max_amount_per_action: {},
    velocity: { config: { window_seconds: 60, max_actions: 10 }, counters: {} }
  };
  const out3 = engine.evaluate(intent, badState3);
  assert.equal(out3.decision, "DENY");
  assert.ok(out3.reasons.includes("STATE_INVALID"));
});
