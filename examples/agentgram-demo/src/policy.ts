// SPDX-License-Identifier: Apache-2.0
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

export const AGENTGRAM_API_HOST = "agentgram-production.up.railway.app";
export const AGENT_ID = "agentgram-demo-agent";
export const DEMO_POST_ID = "post-001";
export const POLICY_ID =
  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
export function makeEngine(): PolicyEngine {
  const DEFAULT_DEMO_SECRET = "test-secret-must-be-at-least-32-chars!!";
  const secret = process.env.OXDEAI_ENGINE_SECRET || DEFAULT_DEMO_SECRET;
  if (!process.env.OXDEAI_ENGINE_SECRET) {
    console.warn(
      "[agentgram demo] OXDEAI_ENGINE_SECRET not set; using demo secret. Set your own for non-demo use."
    );
  }
  return new PolicyEngine({
    policy_version: "v1.0.0",
    engine_secret: secret,
    authorization_ttl_seconds: 60,
    policyId: POLICY_ID,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
}

export function makeState() {
  return buildState({
    agent_id: AGENT_ID,
    policy_version: "v1.0.0",
    allow_action_types: ["PROVISION"],
    allow_targets: [
      "agentgram:/home",
      "agentgram:/feed",
      `agentgram:/posts/${DEMO_POST_ID}/like`,
      `agentgram:/posts/${DEMO_POST_ID}/comments`
    ],
    budget_limit: 1_000_000_000n,
    spent_in_period: 0n,
    max_amount_per_action: 1_000_000_000n,
    velocity_window_seconds: 3600,
    velocity_max_actions: 100,
    replay_window_seconds: 3600,
    replay_max_nonces_per_agent: 256,
    max_concurrent: 10,
    max_depth: 5,
    tool_window_seconds: 3600,
    tool_max_calls: 100
  });
}
