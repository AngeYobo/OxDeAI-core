import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { Authorization } from "@oxdeai/core";
import { makeIntent } from "../helpers/intent.js";
import { makeState } from "../helpers/state.js";

test("authorization signature verifies", () => {
  const secret = "test-secret-must-be-at-least-32-chars!!";
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: secret,
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });

  const intent = makeIntent({
    nonce: 1n,
    amount: 1_000_000n,
    asset: "USDC",
    target: "t1",
    timestamp: 1000
  });

  const state = makeState({
    policy_version: "0.1.0",
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["t1"] },
    budget: { budget_limit: { "agent-1": 10_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 5_000_000n }
  });

  const out = engine.evaluatePure(intent, state, intent.timestamp);
  assert.equal(out.decision, "ALLOW");

  if (out.decision !== "ALLOW") throw new Error("expected ALLOW");

  const v = engine.verifyAuthorization(intent, out.authorization as Authorization, out.nextState, 1000);
  assert.equal(v.valid, true);
});
