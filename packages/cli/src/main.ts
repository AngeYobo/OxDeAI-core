import { PolicyEngine } from "@oxdeai/core";
import type { Intent, State } from "@oxdeai/core";

const secret = process.env.OXDEAI_ENGINE_SECRET ?? "dev-secret";

const engine = new PolicyEngine({
  policy_version: "0.1.0",
  engine_secret: secret,
  authorization_ttl_seconds: 60
});

const now = Math.floor(Date.now() / 1000);

const intent: Intent = {
  intent_id: "intent-1",
  agent_id: "agent-A",
  action_type: "PAYMENT",
  amount: 5_000_000n, // 5.000000 (6 decimals)
  asset: "USDC",
  target: "merchant:coffee",
  timestamp: now,
  metadata_hash: "0x" + "0".repeat(64),
  nonce: 1n,
  signature: "agent-signature-placeholder"
};

const state: State = {
  policy_version: "0.1.0",
  period_id: "2026-02-23",
  kill_switch: { global: false, agents: {} },
  allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant:coffee"] },
  budget: {
    budget_limit: { "agent-A": 10_000_000n },
    spent_in_period: { "agent-A": 0n }
  },
  max_amount_per_action: { "agent-A": 6_000_000n },
  velocity: {
    config: { window_seconds: 60, max_actions: 3 },
    counters: {}
  }
};

const out = engine.evaluate(intent, state);

console.log(
  JSON.stringify(out, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2)
);

if (out.decision === "ALLOW") {
  const v = engine.verifyAuthorization(intent, out.authorization, state, now);
  console.log("verifyAuthorization:", v);
}
