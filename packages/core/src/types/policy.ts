export const Decision = {
  ALLOW: "ALLOW",
  DENY: "DENY"
} as const;

export type Decision = (typeof Decision)[keyof typeof Decision];

export const ReasonCode = {
  KILL_SWITCH: "KILL_SWITCH",
  ALLOWLIST_ACTION: "ALLOWLIST_ACTION",
  ALLOWLIST_ASSET: "ALLOWLIST_ASSET",
  ALLOWLIST_TARGET: "ALLOWLIST_TARGET",
  POLICY_VERSION_MISMATCH: "POLICY_VERSION_MISMATCH",
  STATE_INVALID: "STATE_INVALID",
  BUDGET_EXCEEDED: "BUDGET_EXCEEDED",
  PER_ACTION_CAP_EXCEEDED: "PER_ACTION_CAP_EXCEEDED",
  VELOCITY_EXCEEDED: "VELOCITY_EXCEEDED",
  REPLAY_NONCE: "REPLAY_NONCE",
  REPLAY_DETECTED: "REPLAY_DETECTED",
  AUTH_EXPIRED: "AUTH_EXPIRED",
  AUTH_SIGNATURE_INVALID: "AUTH_SIGNATURE_INVALID",
  AUTH_INTENT_MISMATCH: "AUTH_INTENT_MISMATCH",
  INTERNAL_ERROR: "INTERNAL_ERROR"
} as const;

export type ReasonCode = (typeof ReasonCode)[keyof typeof ReasonCode];

export type PolicyResult =
  | { decision: "ALLOW"; reasons: [] }
  | { decision: "DENY"; reasons: ReasonCode[] };

// Backward-compatible alias for older imports.
export type ModuleResult = PolicyResult;
