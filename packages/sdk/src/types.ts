import type { Authorization, Intent, State, VerificationResult } from "@oxdeai/core";

export type MaybePromise<T> = T | Promise<T>;

export type EvaluateDecision =
  | { decision: "ALLOW"; reasons: []; authorization: Authorization }
  | { decision: "DENY"; reasons: string[] };

export type EvaluateAndCommitResult = {
  output: EvaluateDecision;
  state: State;
  auditEvents: unknown[];
};

export type VerifyBundleResult = {
  snapshot: VerificationResult;
  audit: VerificationResult;
  envelope: VerificationResult;
};

export interface StateAdapter {
  load(): MaybePromise<State>;
  save(state: State): MaybePromise<void>;
}

export interface AuditAdapter {
  append(events: readonly unknown[]): MaybePromise<void>;
}

export interface ClockAdapter {
  now(): number;
}

export type IntentBuilderInput = {
  intent_id: string;
  agent_id: string;
  action_type: Intent["action_type"];
  amount: bigint;
  target: string;
  nonce: bigint;
  timestamp?: number;
  type?: "EXECUTE" | "RELEASE";
  authorization_id?: string;
  asset?: string;
  metadata_hash?: string;
  signature?: string;
  depth?: number;
  tool?: string;
  tool_call?: boolean;
};

export type StateBuilderInput = {
  policy_version?: string;
  period_id?: string;
  agent_id: string;
  allow_action_types?: Intent["action_type"][];
  allow_assets?: string[];
  allow_targets?: string[];
  budget_limit?: bigint;
  spent_in_period?: bigint;
  max_amount_per_action?: bigint;
  velocity_window_seconds?: number;
  velocity_max_actions?: number;
  replay_window_seconds?: number;
  replay_max_nonces_per_agent?: number;
  max_concurrent?: number;
  max_depth?: number;
  tool_window_seconds?: number;
  tool_max_calls?: number;
};
