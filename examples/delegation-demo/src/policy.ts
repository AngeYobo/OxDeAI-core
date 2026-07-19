// SPDX-License-Identifier: Apache-2.0
/**
 * policy.ts - Engine + state setup for the delegation demo.
 *
 * Scenario: Agent A (principal) gets a real PolicyEngine authorization, then
 * delegates narrowed authority to Agent B.
 *
 *   Agent A scope: provision_gpu · up to 100 units (from engine)
 *   Delegation to B: provision_gpu · max 30 units · expiry = parent expiry
 *
 *   Agent B action 1: 20 units  → ALLOW  (within scope)
 *   Agent B action 2: 50 units  → DENY   (exceeds delegation max_amount)
 *
 * The engine is only consulted for Agent A's parent authorization.
 * Agent B's actions are verified locally against the delegation artifact.
 * No engine call for child actions — authority flows without amplification.
 */

import { generateKeyPairSync } from "node:crypto";
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { Intent, State } from "@oxdeai/core";

export const POLICY_ID =
  "demo-delegation-0000000000000000000000000000000000000000000000";

export const AGENT_A = "agent-a";
export const AGENT_B = "agent-b";

// Parent scope: 100 units * 1_000_000 micro-units
export const PARENT_AMOUNT = 100_000_000n;

// Delegation scope: max 30 units
export const DELEGATION_MAX_AMOUNT = 30_000_000n;

// Child actions (in whole units, for display)
export const CHILD_ACTION_1_UNITS = 20;   // ALLOW: 20 ≤ 30
export const CHILD_ACTION_2_UNITS = 50;   // DENY:  50 > 30

// Micro-unit equivalents
export const CHILD_ACTION_1_AMOUNT = BigInt(CHILD_ACTION_1_UNITS * 1_000_000);
export const CHILD_ACTION_2_AMOUNT = BigInt(CHILD_ACTION_2_UNITS * 1_000_000);

// Ed25519 keypair for Agent A to sign the delegation artifact.
// Generated fresh each run; signature verification is not required in this demo.
export const { privateKey: AGENT_A_PRIVATE_KEY_PEM } = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding:  { type: "spki",  format: "pem" },
});

const DEFAULT_DEMO_SECRET = "test-secret-must-be-at-least-32-chars!!";
const _engineSecret = process.env.OXDEAI_ENGINE_SECRET || DEFAULT_DEMO_SECRET;
if (!process.env.OXDEAI_ENGINE_SECRET) {
  console.warn(
    "[delegation demo] OXDEAI_ENGINE_SECRET not set; using demo secret. Set your own for non-demo use."
  );
}

export const engine = new PolicyEngine({
  policy_version: "v1.0.0",
  engine_secret: _engineSecret,
  authorization_ttl_seconds: 300,
  // audience becomes delegation.delegator — set to Agent A's identity
  authorization_audience: AGENT_A,
  policyId: POLICY_ID,
  ...RECOMMENDED_TRUSTED_TIME_PROFILE,
});

export function makeState(): State {
  return {
    policy_version: "v1.0.0",
    period_id: "demo-period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: {
      action_types: ["PROVISION"],
      assets: [],
      targets: ["compute-pool"],
    },
    budget: {
      budget_limit:    { [AGENT_A]: 1_000_000_000n },
      spent_in_period: { [AGENT_A]: 0n },
    },
    max_amount_per_action: { [AGENT_A]: PARENT_AMOUNT },
    velocity: {
      config: { window_seconds: 3600, max_actions: 100 },
      counters: {},
    },
    replay: {
      window_seconds: 3600,
      max_nonces_per_agent: 256,
      nonces: {},
    },
    concurrency: {
      max_concurrent: { [AGENT_A]: 5 },
      active: {},
      active_auths: {},
    },
    recursion: { max_depth: { [AGENT_A]: 5 } },
    tool_limits: {
      window_seconds: 3600,
      max_calls: { [AGENT_A]: 100 },
      calls: {},
    },
  };
}

export function buildParentIntent(
  timestampSeconds: number,
  nonce: bigint
): Extract<Intent, { type?: "EXECUTE" }> {
  return {
    type: "EXECUTE",
    intent_id: "parent-provision-gpu-agent-a",
    agent_id: AGENT_A,
    action_type: "PROVISION",
    amount: PARENT_AMOUNT,
    target: "compute-pool",
    timestamp: timestampSeconds,
    metadata_hash: "0".repeat(64),
    nonce,
    signature: "agent-a-sig-placeholder",
    tool: "provision_gpu",
    tool_call: true,
    depth: 0,
  };
}

export function buildChildIntent(
  agentId: string,
  amount: bigint,
  timestampSeconds: number,
  nonce: bigint
): Extract<Intent, { type?: "EXECUTE" }> {
  return {
    type: "EXECUTE",
    intent_id: `child-provision-gpu-${agentId}-${String(nonce)}`,
    agent_id: agentId,
    action_type: "PROVISION",
    amount,
    target: "compute-pool",
    timestamp: timestampSeconds,
    metadata_hash: "0".repeat(64),
    nonce,
    signature: `${agentId}-sig-placeholder`,
    tool: "provision_gpu",
    tool_call: true,
    depth: 1,
  };
}
