import type { ActionType } from "./intent.js";

/** @public */
export type KillSwitchState = {
  global: boolean;
  agents: Record<string, boolean | undefined>;
};

/** @public */
export type AllowLists = {
  action_types?: ActionType[];
  assets?: string[];
  targets?: string[];
};

/** @public */
export type BudgetState = {
  // per agent per period
  budget_limit: Record<string, bigint | undefined>;
  spent_in_period: Record<string, bigint | undefined>;
};

/** @public */
export type VelocityConfig = {
  window_seconds: number; // Δt
  max_actions: number; // max actions in window
};

/** @public */
export type VelocityCounters = Record<
  string,
  { window_start: number; count: number } | undefined
>;

/** @public */
export type RecursionState = {
  max_depth: Record<string, number | undefined>;
};

/** @public */
export type ToolLimitsState = {
  window_seconds: number;
  max_calls: Record<string, number | undefined>;
  max_calls_by_tool?: Record<string, Record<string, number | undefined> | undefined>;
  calls: Record<string, Array<{ ts: number; tool?: string }> | undefined>;
};

/** @public */
export type State = {
  policy_version: string;
  period_id: string;

   kill_switch: {
    global: boolean;
    agents: Record<string, boolean>;
  };
  
  allowlists: AllowLists;

  budget: {
    budget_limit: Record<string, bigint>;
    spent_in_period: Record<string, bigint>;
  };

  // INV-2 Per-action cap (hard cap)
  max_amount_per_action: Record<string, bigint | undefined>;

  velocity: {
    config: VelocityConfig;
    counters: VelocityCounters;
  };

  replay: {
    window_seconds: number;           // e.g. 3600
    max_nonces_per_agent: number;     // e.g. 256
    nonces: Record<string, Array<{ nonce: string; ts: number }>>; // per agent
  };

  concurrency: {
    max_concurrent: Record<string, number>;     // per agent
    active: Record<string, number>;             // per agent
    active_auths: Record<string, Record<string, { expires_at: number }>>;
  };
  recursion: {
    max_depth: Record<string, number>;        // per agent
  };

  tool_limits?: ToolLimitsState;
};

/** @public */
export type StateHash = string;

/** @public */
export type CanonicalState = {
  formatVersion: 1;
  engineVersion: string;
  policyId: string;
  modules: Record<string, unknown>;
};

/** @public */
export interface ModuleStateCodec {
  moduleId: string;
  serializeState(state: State): unknown;
  deserializeState(state: State, payload: unknown): void;
  stateHash(state: State): StateHash;
}
