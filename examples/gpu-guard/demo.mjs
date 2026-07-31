import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "../../packages/core/dist/index.js";

const DEFAULT_DEMO_SECRET = "test-secret-must-be-at-least-32-chars!!";
const _engineSecret = process.env.OXDEAI_ENGINE_SECRET || DEFAULT_DEMO_SECRET;
if (!process.env.OXDEAI_ENGINE_SECRET) {
  console.warn(
    "[gpu-guard demo] OXDEAI_ENGINE_SECRET not set; using demo secret. Set your own for non-demo use."
  );
}

// Stable demo timestamp - no Date.now(), output is fully deterministic.
// Supplied as the trusted evaluation time; the intent carries the same value.
const DEMO_EVALUATION_TIME = 1730000000; // 2024-10-27T04:53:20Z

const engine = new PolicyEngine({
  policy_version: "v1.0.0",
  engine_secret: _engineSecret,
  authorization_ttl_seconds: 60,
  policyId: "a".repeat(64),
  ...RECOMMENDED_TRUSTED_TIME_PROFILE
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
  timestamp: DEMO_EVALUATION_TIME,
  metadata_hash: "0".repeat(64),
  nonce: 1n,
  signature: "sig",
  type: "EXECUTE",
  depth: 0,
  tool_call: true,
  tool: "aws.ec2.runInstances"
};

const out = engine.evaluatePure(intent, state, DEMO_EVALUATION_TIME, { mode: "fail-fast" });

console.log("decision:", out.decision);
if (out.decision === "ALLOW") {
  console.log("auth_id:", out.authorization.auth_id);
  console.log("policyId:", engine.computePolicyId());
  console.log("stateHash:", engine.computeStateHash(out.nextState));
  console.log("auditHeadHash:", engine.audit.headHash());
} else {
  console.log("reasons:", out.reasons.join(","));
}
