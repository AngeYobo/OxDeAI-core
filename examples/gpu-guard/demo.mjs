import { PolicyEngine } from "../../packages/core/dist/index.js";

const engine = new PolicyEngine({
  policy_version: "v1.0.0",
  engine_secret: "demo-secret",
  authorization_ttl_seconds: 60,
  policyId: "a".repeat(64)
});

const state = {
  policy_version: "v1.0.0",
  period_id: "2026-03",
  kill_switch: { global: false, agents: {} },
  allowlists: {
    action_types: ["PROVISION"],
    targets: ["gpu:a100"]
  },
  budget: {
    budget_limit: { "agent-1": 10_000_000n },
    spent_in_period: { "agent-1": 0n }
  },
  max_amount_per_action: { "agent-1": 2_000_000n },
  velocity: { config: { window_seconds: 60, max_actions: 100 }, counters: {} },
  replay: { window_seconds: 300, max_nonces_per_agent: 256, nonces: {} },
  concurrency: { max_concurrent: { "agent-1": 2 }, active: {}, active_auths: {} },
  recursion: { max_depth: { "agent-1": 2 } },
  tool_limits: { window_seconds: 60, max_calls: { "agent-1": 1000 }, calls: {} }
};

const intent = {
  intent_id: "gpu-demo-1",
  agent_id: "agent-1",
  action_type: "PROVISION",
  amount: 1_500_000n,
  target: "gpu:a100",
  timestamp: 1730000000,
  metadata_hash: "0".repeat(64),
  nonce: 1n,
  signature: "sig",
  type: "EXECUTE",
  depth: 0,
  tool_call: true,
  tool: "aws.ec2.runInstances"
};

const out = engine.evaluatePure(intent, state, { mode: "fail-fast" });

console.log("decision:", out.decision);
if (out.decision === "ALLOW") {
  console.log("authorization_id:", out.authorization.authorization_id);
  console.log("policyId:", engine.computePolicyId());
  console.log("stateHash:", engine.computeStateHash(out.nextState));
  console.log("auditHeadHash:", engine.audit.headHash());
} else {
  console.log("reasons:", out.reasons.join(","));
}
