// SPDX-License-Identifier: Apache-2.0
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { Intent, State } from "@oxdeai/core";
import { DEMO_KEYSET, DEMO_PRIVATE_KEY_PEM } from "./crypto.js";

export const GPU_COST: Record<string, Record<string, bigint>> = {
  a100: { "us-east-1": 500n },
  h100: { "us-east-1": 900n },
};

export function gpuCost(asset: string, region: string): bigint {
  const cost = GPU_COST[asset]?.[region];
  if (cost === undefined) throw new Error(`Unknown GPU cost: ${asset}/${region}`);
  return cost;
}

export const POLICY_ID =
  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

export const AGENT_ID = "gpu-agent-1";

const DEFAULT_DEMO_SECRET = "test-secret-must-be-at-least-32-chars!!";
const _engineSecret = process.env.OXDEAI_ENGINE_SECRET || DEFAULT_DEMO_SECRET;
if (!process.env.OXDEAI_ENGINE_SECRET) {
  console.warn(
    "[crewai demo] OXDEAI_ENGINE_SECRET not set; using demo secret. Set your own for non-demo use."
  );
}

export const engine = new PolicyEngine({
  policy_version: "v1.0.0",
  engine_secret: _engineSecret,
  authorization_signing_alg: "Ed25519",
  authorization_signing_kid: "k1",
  authorization_issuer: DEMO_KEYSET.issuer,
  authorization_private_key_pem: DEMO_PRIVATE_KEY_PEM,
  authorization_ttl_seconds: 600,
  authorization_audience: AGENT_ID,
  policyId: POLICY_ID,
  ...RECOMMENDED_TRUSTED_TIME_PROFILE,
});

export function makeState(): State {
  return {
    policy_version: "v1.0.0",
    period_id: "period-demo",
    kill_switch: { global: false, agents: {} },
    allowlists: {
      action_types: ["PROVISION"],
      assets: ["a100"],
      targets: ["us-east-1"],
    },
    budget: {
      budget_limit: { [AGENT_ID]: 1_000n },
      spent_in_period: { [AGENT_ID]: 0n },
    },
    max_amount_per_action: { [AGENT_ID]: 500n },
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
      max_concurrent: { [AGENT_ID]: 5 },
      active: {},
      active_auths: {},
    },
    recursion: { max_depth: { [AGENT_ID]: 5 } },
    tool_limits: {
      window_seconds: 3600,
      max_calls: { [AGENT_ID]: 100 },
      calls: {},
    },
  };
}

let nonceCounter = 1n;

export function buildProvisionIntent(
  asset: string,
  region: string,
  timestampSeconds: number
): Extract<Intent, { type?: "EXECUTE" }> {
  const nonce = nonceCounter++;
  const amount = gpuCost(asset, region);
  return {
    intent_id: `intent-gpu-${nonce}`,
    agent_id: AGENT_ID,
    action_type: "PROVISION",
    type: "EXECUTE",
    amount,
    asset,
    target: region,
    timestamp: timestampSeconds,
    metadata_hash: "0".repeat(64),
    nonce,
    signature: "agent-sig-placeholder",
    tool: "provision_gpu",
    tool_call: true,
    depth: 0,
  };
}
