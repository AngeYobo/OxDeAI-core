import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine } from "@oxdeai/core";
import { makeIntent } from "../helpers/intent.js";
import { makeState } from "../helpers/state.js";

test("INV-3 Velocity denies when exceeded in window", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "s",
    authorization_ttl_seconds: 60
  });

  const state = makeState({
    policy_version: "0.1.0",
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["t1"] },
    budget: { budget_limit: { "agent-1": 100_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 5_000_000n },
    velocity: {
      config: { window_seconds: 60, max_actions: 3 },
      counters: { "agent-1": { window_start: 980, count: 3 } }
    }
  });
  const intent = makeIntent({
    nonce: 1n,
    amount: 1_000_000n,
    asset: "USDC",
    target: "t1",
    timestamp: 1000
  });

  const out = engine.evaluatePure(intent, state);
  assert.equal(out.decision, "DENY");
  assert.ok(out.reasons.includes("VELOCITY_EXCEEDED"));
});
