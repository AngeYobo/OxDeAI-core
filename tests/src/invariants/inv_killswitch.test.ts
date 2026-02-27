import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine } from "@oxdeai/core";
import { makeIntent } from "../helpers/intent.js";
import { makeState } from "../helpers/state.js";

test("INV-4 Kill switch denies deterministically", () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "s",
    authorization_ttl_seconds: 60
  });

  const state = makeState({
    policy_version: "0.1.0",
    kill_switch: { global: true, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["t1"] }
  });
  const intent = makeIntent({
    nonce: 2n,
    amount: 1_000_000n,
    asset: "USDC",
    target: "t1",
    timestamp: 1000
  });

  const out = engine.evaluatePure(intent, state);
  assert.equal(out.decision, "DENY");
  assert.ok(out.reasons.includes("KILL_SWITCH"));
});
