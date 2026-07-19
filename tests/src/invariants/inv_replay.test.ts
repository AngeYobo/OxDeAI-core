import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import { makeIntent } from "../helpers/intent.js";
import { makeState } from "../helpers/state.js";

test("INV-Replay: same (agent, nonce) cannot execute twice", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });

  const state = makeState({
    policy_version: "0.1.0",
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant"] },
    budget: { budget_limit: { "agent-1": 10_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 5_000_000n }
  });
  const intent = makeIntent({
    intent_id: "intent-1",
    nonce: 77n,
    amount: 1_000_000n,
    asset: "USDC",
    target: "merchant",
    timestamp: 1000
  });

  // First execution should pass
  const first = engine.evaluatePure(intent, state, intent.timestamp);
  assert.equal(first.decision, "ALLOW");
  if (first.decision !== "ALLOW") throw new Error("expected ALLOW");

  // Second execution with SAME nonce must fail
  const second = engine.evaluatePure(intent, first.nextState, intent.timestamp);
  assert.equal(second.decision, "DENY");
  assert.ok(second.reasons.includes("REPLAY_NONCE") || second.reasons.includes("REPLAY_DETECTED"));
});
