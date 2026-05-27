// SPDX-License-Identifier: Apache-2.0
// packages/core/src/dev/decision-subprocess.ts
//
// Deterministic decision-path subprocess used by cross_process.test.ts (D-5).
//
// Runs a fixed, fully-specified intent sequence against a fixed state and
// writes the result to OXDEAI_DECISION_OUT as JSON:
//
//   {
//     decisions:      string[],
//     authIds:        (string | null)[],
//     finalStateHash: string,
//     policyId:       string,
//     auditHeadHash:  string
//   }
//
// Nothing here is random or environment-dependent.  Two invocations of this
// script in separate Node processes must always produce identical output.

import { writeFile } from "node:fs/promises";
import { PolicyEngine } from "../policy/PolicyEngine.js";
import type { State } from "../types/state.js";
import type { Intent } from "../types/intent.js";

const POLICY = "v-xp-test";

function makeState(): State {
  return {
    policy_version: POLICY,
    period_id: "2025-01",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit: { "agent-a": 100_000n, "agent-b": 50_000n },
      spent_in_period: { "agent-a": 0n, "agent-b": 0n }
    },
    max_amount_per_action: { "agent-a": 10_000n, "agent-b": 5_000n },
    velocity: { config: { window_seconds: 60, max_actions: 10 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: {
      max_concurrent: { "agent-a": 3, "agent-b": 2 },
      active: {},
      active_auths: {}
    },
    recursion: { max_depth: { "agent-a": 3, "agent-b": 2 } },
    tool_limits: {
      window_seconds: 60,
      max_calls: { "agent-a": 5, "agent-b": 5 },
      calls: {}
    }
  };
}

// Fixed intent sequence — all fields fully specified, no entropy.
const INTENTS: Intent[] = [
  {
    intent_id: "xp-1", agent_id: "agent-a", action_type: "PAYMENT",
    target: "vendor-x", metadata_hash: "0".repeat(64), signature: "",
    type: "EXECUTE", nonce: 1n, amount: 500n, timestamp: 1_700_000_001, depth: 0
  },
  {
    intent_id: "xp-2", agent_id: "agent-b", action_type: "PURCHASE",
    target: "vendor-y", metadata_hash: "0".repeat(64), signature: "",
    type: "EXECUTE", nonce: 2n, amount: 200n, timestamp: 1_700_000_002, depth: 0,
    tool_call: true, tool: "openai.responses"
  },
  {
    intent_id: "xp-3", agent_id: "agent-a", action_type: "PROVISION",
    target: "vendor-z", metadata_hash: "0".repeat(64), signature: "",
    type: "EXECUTE", nonce: 3n, amount: 100n, timestamp: 1_700_000_003, depth: 1
  },
  {
    intent_id: "xp-4", agent_id: "agent-b", action_type: "PAYMENT",
    target: "vendor-x", metadata_hash: "0".repeat(64), signature: "",
    type: "EXECUTE", nonce: 4n, amount: 300n, timestamp: 1_700_000_004, depth: 0
  },
  // Replay: same nonce as xp-1 — must DENY
  {
    intent_id: "xp-5", agent_id: "agent-a", action_type: "PAYMENT",
    target: "vendor-x", metadata_hash: "0".repeat(64), signature: "",
    type: "EXECUTE", nonce: 1n, amount: 500n, timestamp: 1_700_000_005, depth: 0
  },
  {
    intent_id: "xp-6", agent_id: "agent-a", action_type: "PAYMENT",
    target: "vendor-x", metadata_hash: "0".repeat(64), signature: "",
    type: "EXECUTE", nonce: 5n, amount: 800n, timestamp: 1_700_000_006, depth: 0,
    tool_call: true, tool: "stripe.charge"
  }
];

async function main(): Promise<void> {
  const engine = new PolicyEngine({
    policy_version: POLICY,
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 300
  });

  const decisions: string[] = [];
  const authIds: (string | null)[] = [];
  let state = makeState();
  // RELEASE intents reference prior authorization IDs.
  const authQueue: Record<string, string[]> = {};

  for (const intent of INTENTS) {
    // Wire up RELEASE intents to prior auth IDs if needed.
    let actual = intent;
    if (intent.type === "RELEASE") {
      const queue = authQueue[intent.agent_id] ?? [];
      const authorization_id = queue.shift();
      if (authorization_id) {
        authQueue[intent.agent_id] = queue;
        actual = { ...intent, authorization_id };
      } else {
        actual = { ...intent, type: "EXECUTE" };
      }
    }

    const out = engine.evaluatePure(actual, state, { mode: "fail-fast" });
    decisions.push(out.decision);

    if (out.decision === "ALLOW") {
      authIds.push(out.authorization.auth_id);
      state = out.nextState;
      if (actual.type !== "RELEASE") {
        const queue = authQueue[actual.agent_id] ?? [];
        queue.push(out.authorization.auth_id);
        authQueue[actual.agent_id] = queue;
      }
    } else {
      authIds.push(null);
    }
  }

  const finalStateHash = engine.computeStateHash(state);
  const policyId = engine.computePolicyId();
  const auditHeadHash = engine.audit.headHash();
  const output = { decisions, authIds, finalStateHash, policyId, auditHeadHash };

  if (process.env["OXDEAI_DECISION_OUT"]) {
    await writeFile(process.env["OXDEAI_DECISION_OUT"], JSON.stringify(output));
  } else {
    process.stdout.write(JSON.stringify(output) + "\n");
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
