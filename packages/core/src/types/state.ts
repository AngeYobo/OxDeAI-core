import type { ActionType } from "./intent.js";

export type KillSwitchState = {
  global: boolean;
  agents: Record<string, boolean | undefined>;
};

export type AllowLists = {
  action_types?: ActionType[];
  assets?: string[];
  targets?: string[];
};

export type BudgetState = {
  // per agent per period
  budget_limit: Record<string, bigint | undefined>;
  spent_in_period: Record<string, bigint | undefined>;
};

export type VelocityConfig = {
  window_seconds: number; // Δt
  max_actions: number; // max actions in window
};

export type VelocityCounters = Record<
  string,
  { window_start: number; count: number } | undefined
>;

export type State = {
  policy_version: string;
  period_id: string;

  kill_switch: KillSwitchState;
  allowlists: AllowLists;

  budget: BudgetState;

  // INV-2 Per-action cap (hard cap)
  max_amount_per_action: Record<string, bigint | undefined>;

  velocity: {
    config: VelocityConfig;
    counters: VelocityCounters;
  };
};