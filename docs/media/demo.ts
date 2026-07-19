import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE, verifyAuthorization } from "@oxdeai/core";
import type { Intent, State } from "@oxdeai/core";

const FIXED_TIMESTAMP = 1_730_000_000;

const _engineSecret = process.env.OXDEAI_ENGINE_SECRET ?? "";
if (!_engineSecret) throw new Error("Missing required env var: OXDEAI_ENGINE_SECRET");

const engine = new PolicyEngine({
  policy_version: "v1.6",
  engine_secret: _engineSecret,
  authorization_ttl_seconds: 60,
  ...RECOMMENDED_TRUSTED_TIME_PROFILE
});

const initialState: State = {
  policy_version: "v1.6",
  period_id: "2026-03",
  kill_switch: { global: false, agents: {} },
  allowlists: {},
  budget: {
    budget_limit: { "agent-1": 1_000n },
    spent_in_period: { "agent-1": 0n }
  },
  max_amount_per_action: { "agent-1": 100n },
  velocity: {
    config: { window_seconds: 60, max_actions: 100 },
    counters: {}
  },
  replay: {
    window_seconds: 3_600,
    max_nonces_per_agent: 256,
    nonces: {}
  },
  concurrency: {
    max_concurrent: { "agent-1": 2 },
    active: {},
    active_auths: {}
  },
  recursion: {
    max_depth: { "agent-1": 2 }
  },
  tool_limits: {
    window_seconds: 60,
    max_calls: { "agent-1": 100 },
    calls: {}
  }
};

const intent: Intent = {
  intent_id: "intent-charge-wallet-001",
  agent_id: "agent-1",
  action_type: "PAYMENT",
  target: "user_123",
  metadata_hash: "0".repeat(64),
  signature: "",
  type: "EXECUTE",
  tool_call: true,
  tool: "charge_wallet",
  nonce: 1n,
  amount: 10n,
  timestamp: FIXED_TIMESTAMP,
  depth: 0
};

function printProposal(): void {
  console.log("agent -> propose charge_wallet(user_123, 10)");
  console.log();
}

function printSeparator(): void {
  console.log();
  console.log("---");
  console.log();
}

function main(): void {
  printProposal();

  const first = engine.evaluatePure(intent, initialState, FIXED_TIMESTAMP, { mode: "fail-fast" });
  if (first.decision !== "ALLOW") {
    throw new Error(`Expected first decision to ALLOW, got DENY: ${first.reasons.join(", ")}`);
  }

  console.log("[Decision]");
  console.log("(intent, state, policy) -> ALLOW");
  console.log();
  console.log("[AuthorizationV1 issued]");
  console.log();

  const verified = verifyAuthorization(first.authorization, {
    now: FIXED_TIMESTAMP,
    expectedPolicyId: engine.computePolicyId(),
    legacyHmacSecret: _engineSecret,
    requireSignatureVerification: true
  });

  if (!verified.ok) {
    throw new Error(`Expected verifyAuthorization() -> ok, got ${verified.status}`);
  }

  console.log("[PEP] verifyAuthorization() -> ok");
  console.log();
  console.log("[Execution] SUCCESS");

  printSeparator();
  printProposal();

  const second = engine.evaluatePure(intent, first.nextState, FIXED_TIMESTAMP, { mode: "fail-fast" });
  if (second.decision !== "DENY" || !second.reasons.includes("REPLAY_NONCE")) {
    throw new Error(`Expected second decision to DENY with REPLAY_NONCE, got ${second.decision}: ${second.reasons.join(", ")}`);
  }

  console.log("[Decision]");
  console.log("(intent, state, policy) -> DENY (REPLAY)");
  console.log();
  console.log("[Blocked before execution]");
  console.log();
  console.log("---");
}

main();
