// SPDX-License-Identifier: Apache-2.0
/**
 * policy.ts - Engine + state setup for the execution boundary demo.
 *
 * Scenario: an agent charges a user wallet.
 * The same intent is evaluated twice. Budget is ample and the tool is always
 * on the allowlist — only the execution state changes between evaluations.
 */

import { generateKeyPairSync } from "node:crypto";
import { PolicyEngine } from "@oxdeai/core";
import type { Intent, KeySet, State } from "@oxdeai/core";

export const POLICY_ID =
  "demo-execution-boundary-0000000000000000000000000000000000000000000000";

export const AGENT_ID = "payment-agent-1";

export const AUTH_ISSUER = "execution-boundary-demo-issuer";
export const AUTH_KID = "execution-boundary-demo-k1";

const DEMO_AUTH_KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

export const TRUSTED_KEYSETS: KeySet[] = [
  {
    issuer: AUTH_ISSUER,
    version: "1",
    keys: [
      {
        kid: AUTH_KID,
        alg: "Ed25519",
        public_key: DEMO_AUTH_KEYPAIR.publicKey.toString(),
      },
    ],
  },
];

// Fixed nonce - same value across both calls, making the intent structurally identical.
export const CHARGE_NONCE = 42n;

// 10 units * 1_000_000 micro-units (matching defaultNormalizeAction convention)
export const CHARGE_AMOUNT = 10_000_000n;

// Starting wallet display balance (domain concept, separate from engine budget)
export const WALLET_START = 100;

const DEFAULT_DEMO_SECRET = "test-secret-must-be-at-least-32-chars!!";
const _engineSecret = process.env.OXDEAI_ENGINE_SECRET || DEFAULT_DEMO_SECRET;
if (!process.env.OXDEAI_ENGINE_SECRET) {
  console.warn(
    "[execution-boundary demo] OXDEAI_ENGINE_SECRET not set; using demo secret. Set your own for non-demo use."
  );
}

export const engine = new PolicyEngine({
  policy_version: "v1.0.0",
  engine_secret: _engineSecret,
  authorization_ttl_seconds: 60,
  authorization_audience: AGENT_ID,
  authorization_issuer: AUTH_ISSUER,
  authorization_signing_alg: "Ed25519",
  authorization_signing_kid: AUTH_KID,
  authorization_private_key_pem: DEMO_AUTH_KEYPAIR.privateKey.toString(),
  policyId: POLICY_ID,
});

export function makeState(): State {
  return {
    policy_version: "v1.0.0",
    period_id: "demo-period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: {
      action_types: ["PAYMENT"],
      assets: ["wallet"],
      targets: ["user_123"],
    },
    budget: {
      // Ample budget - not the limiting factor in this demo
      budget_limit: { [AGENT_ID]: 1_000_000_000n },
      spent_in_period: { [AGENT_ID]: 0n },
    },
    max_amount_per_action: { [AGENT_ID]: 100_000_000n },
    velocity: {
      config: { window_seconds: 3600, max_actions: 100 },
      counters: {},
    },
    replay: {
      window_seconds: 3600,
      max_nonces_per_agent: 256,
      nonces: {}, // recorded after the first ALLOW; makes the second evaluation state-inconsistent
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

export function buildChargeIntent(
  timestampSeconds: number
): Extract<Intent, { type?: "EXECUTE" }> {
  return {
    type: "EXECUTE",
    intent_id: "charge-user123-order42",
    agent_id: AGENT_ID,
    action_type: "PAYMENT",
    amount: CHARGE_AMOUNT,
    asset: "wallet",
    target: "user_123",
    timestamp: timestampSeconds,
    metadata_hash: "0".repeat(64),
    nonce: CHARGE_NONCE, // same across both calls — intent is structurally identical each time
    signature: "agent-sig-placeholder",
    tool: "charge_wallet",
    tool_call: true,
    depth: 0,
  };
}
