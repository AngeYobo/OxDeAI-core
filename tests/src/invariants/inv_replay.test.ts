import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine } from "@oxdeai/core";
import type { Intent, State } from "@oxdeai/core";

test("INV-Replay: same (agent, nonce) cannot execute twice", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "replay-secret",
    authorization_ttl_seconds: 60
  });

  const now = 1000;

  const intent: Intent = {
    intent_id: "intent-1",
    agent_id: "agent-A",
    action_type: "PAYMENT",
    amount: 1_000_000n,
    asset: "USDC",
    target: "merchant",
    timestamp: now,
    metadata_hash: "0x" + "0".repeat(64),
    nonce: 42n,
    signature: "sig"
  };

  const state: State = {
    policy_version: "0.1.0",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant"] },
    budget: { budget_limit: { "agent-A": 10_000_000n }, spent_in_period: { "agent-A": 0n } },
    max_amount_per_action: { "agent-A": 5_000_000n },
    velocity: { config: { window_seconds: 60, max_actions: 10 }, counters: {} }
  };

  // First execution should pass
  const first = engine.evaluate(intent, state);
  assert.equal(first.decision, "ALLOW");

  // Second execution with SAME nonce must fail
  const second = engine.evaluate(intent, state);
  assert.equal(second.decision, "DENY");
  assert.ok(second.reasons.includes("REPLAY_NONCE"));
});
