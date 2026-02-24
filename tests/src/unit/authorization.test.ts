import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine } from "@oxdeai/core";
import type { Intent, State } from "@oxdeai/core";

test("authorization signature verifies", () => {
  const secret = "unit-secret";
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: secret,
    authorization_ttl_seconds: 60
  });

  const now = 1000;

  const intent: Intent = {
    intent_id: "i1",
    agent_id: "a1",
    action_type: "PAYMENT",
    amount: 1_000_000n,
    asset: "USDC",
    target: "t1",
    timestamp: now,
    metadata_hash: "0x" + "0".repeat(64),
    nonce: 1n,
    signature: "sig"
  };

  const state: State = {
    policy_version: "0.1.0",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["t1"] },
    budget: { budget_limit: { a1: 10_000_000n }, spent_in_period: { a1: 0n } },
    max_amount_per_action: { a1: 5_000_000n },
    velocity: { config: { window_seconds: 60, max_actions: 10 }, counters: {} }
  };

  const out = engine.evaluate(intent, state);
  assert.equal(out.decision, "ALLOW");

  if (out.decision !== "ALLOW") throw new Error("expected ALLOW");

  const v = engine.verifyAuthorization(intent, out.authorization, state, now);
  assert.equal(v.valid, true);
});
