import type { State, ToolLimitsState } from "@oxdeai/core";

export function makeState(overrides: Partial<State> = {}): State {
  const baseToolLimits: ToolLimitsState = {
    window_seconds: 60,
    max_calls: { "agent-1": 1_000_000 },
    calls: {}
  };

  const base: State = {
    policy_version: "v0.4",
    period_id: "test-period",

    kill_switch: { global: false, agents: {} },
    allowlists: {},

    budget: {
      budget_limit: { "agent-1": 10_000n },
      spent_in_period: { "agent-1": 0n }
    },

    max_amount_per_action: { "agent-1": 5_000n },

    velocity: {
      config: { window_seconds: 60, max_actions: 1_000_000 },
      counters: {}
    },

    replay: {
      window_seconds: 3600,
      max_nonces_per_agent: 10_000,
      nonces: {}
    },

    concurrency: {
      max_concurrent: { "agent-1": 1_000_000 },
      active: {},
      active_auths: {}
    },

    recursion: {
      max_depth: { "agent-1": 1_000_000 }
    },

    tool_limits: baseToolLimits
  };

  const tl = overrides.tool_limits;
  const tool_limits: ToolLimitsState = {
    window_seconds: tl?.window_seconds ?? baseToolLimits.window_seconds,
    max_calls: tl?.max_calls ?? baseToolLimits.max_calls,
    calls: tl?.calls ?? baseToolLimits.calls,
    ...(tl?.max_calls_by_tool !== undefined
      ? { max_calls_by_tool: tl.max_calls_by_tool }
      : baseToolLimits.max_calls_by_tool !== undefined
        ? { max_calls_by_tool: baseToolLimits.max_calls_by_tool }
        : {})
  };

  return {
    ...base,
    ...overrides,
    kill_switch: { ...base.kill_switch, ...(overrides.kill_switch ?? {}) },
    budget: { ...base.budget, ...(overrides.budget ?? {}) },
    velocity: { ...base.velocity, ...(overrides.velocity ?? {}) },
    replay: { ...base.replay, ...(overrides.replay ?? {}) },
    concurrency: { ...base.concurrency, ...(overrides.concurrency ?? {}) },
    recursion: { ...base.recursion, ...(overrides.recursion ?? {}) },
    tool_limits
  };
}
