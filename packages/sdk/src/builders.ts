import type { Intent, State } from "@oxdeai/core";
import type { IntentBuilderInput, StateBuilderInput } from "./types.js";

export function buildIntent(input: IntentBuilderInput): Intent {
  const base = {
    intent_id: input.intent_id,
    agent_id: input.agent_id,
    action_type: input.action_type,
    amount: input.amount,
    asset: input.asset,
    target: input.target,
    timestamp: input.timestamp ?? 0,
    metadata_hash: input.metadata_hash ?? "0x" + "0".repeat(64),
    nonce: input.nonce,
    signature: input.signature ?? "sdk-signature-placeholder",
    depth: input.depth,
    tool: input.tool,
    tool_call: input.tool_call
  };

  if (input.type === "RELEASE") {
    if (!input.authorization_id) throw new Error("authorization_id is required for RELEASE intent");
    return {
      ...base,
      type: "RELEASE",
      authorization_id: input.authorization_id
    };
  }

  return {
    ...base,
    type: "EXECUTE",
    authorization_id: input.authorization_id
  };
}

export function buildState(input: StateBuilderInput): State {
  const agent = input.agent_id;
  return {
    policy_version: input.policy_version ?? "v1",
    period_id: input.period_id ?? "default-period",
    kill_switch: { global: false, agents: {} },
    allowlists: {
      action_types: input.allow_action_types ?? ["PROVISION"],
      assets: input.allow_assets ?? [],
      targets: input.allow_targets ?? []
    },
    budget: {
      budget_limit: { [agent]: input.budget_limit ?? 1_000_000n },
      spent_in_period: { [agent]: input.spent_in_period ?? 0n }
    },
    max_amount_per_action: { [agent]: input.max_amount_per_action ?? 1_000_000n },
    velocity: {
      config: {
        window_seconds: input.velocity_window_seconds ?? 60,
        max_actions: input.velocity_max_actions ?? 1000
      },
      counters: {}
    },
    replay: {
      window_seconds: input.replay_window_seconds ?? 3600,
      max_nonces_per_agent: input.replay_max_nonces_per_agent ?? 256,
      nonces: {}
    },
    concurrency: {
      max_concurrent: { [agent]: input.max_concurrent ?? 16 },
      active: {},
      active_auths: {}
    },
    recursion: {
      max_depth: { [agent]: input.max_depth ?? 8 }
    },
    tool_limits: {
      window_seconds: input.tool_window_seconds ?? 60,
      max_calls: { [agent]: input.tool_max_calls ?? 1000 },
      max_calls_by_tool: {},
      calls: {}
    }
  };
}
