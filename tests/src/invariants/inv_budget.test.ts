import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine } from "@oxdeai/core";
import { makeIntent } from "../helpers/intent.js";
import { makeState } from "../helpers/state.js";

test("INV-1 Budget Safety denies when exceeded", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "s",
    authorization_ttl_seconds: 60
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

  const out = engine.evaluatePure(intent, state);
  assert.equal(out.decision, "DENY");
  assert.ok(out.reasons.includes("BUDGET_EXCEEDED"));
});

test("INV-2 Per-action cap denies when exceeded", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "s",
    authorization_ttl_seconds: 60
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

  const out = engine.evaluatePure(intent, state);
  assert.equal(out.decision, "DENY");
  assert.ok(out.reasons.includes("PER_ACTION_CAP_EXCEEDED"));
});
