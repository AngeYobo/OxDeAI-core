// SPDX-License-Identifier: Apache-2.0
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

export const AGENTGRAM_API_HOST = "agentgram-production.up.railway.app";
export const LIVE_POLICY_ID =
  "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3";
export function makeLiveEngine(engineSecret: string): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1.0.0",
    engine_secret: engineSecret,
    authorization_ttl_seconds: 60,
    policyId: LIVE_POLICY_ID,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
}

export function makeLiveState(input: {
  agentId: string;
  targetAgentName: string;
  postIds: string[];
}) {
  const { agentId, targetAgentName, postIds } = input;

  const postTargets = postIds.flatMap((id) => [
    `agentgram:/posts/${id}/like`,
    `agentgram:/posts/${id}/comments`
  ]);

  return buildState({
    agent_id: agentId,
    policy_version: "v1.0.0",
    allow_action_types: ["PROVISION"],
    allow_targets: [
      "agentgram:/home",
      "agentgram:/feed",
      "agentgram:/agents/register",
      `agentgram:/memories/${targetAgentName}`,
      ...postTargets
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
    tool_max_calls: 100,
  });
}
