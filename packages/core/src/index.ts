// packages/core/src/index.ts

// ─────────────────────────────────────────────────────────────
// Protocol / verification surface (v1.0 contract)
// ─────────────────────────────────────────────────────────────
export type * from "./verification/types.js";
export { verifySnapshot } from "./verification/verifySnapshot.js";
export { verifyAuditEvents } from "./verification/verifyAuditEvents.js";
export { encodeEnvelope, decodeEnvelope } from "./verification/envelope.js";
export { verifyEnvelope } from "./verification/verifyEnvelope.js";

// Portable canonical snapshot codec
export { encodeCanonicalState, decodeCanonicalState } from "./snapshot/CanonicalCodec.js";

// ─────────────────────────────────────────────────────────────
// Engine + core domain types (runtime evaluator)
// ─────────────────────────────────────────────────────────────
export { PolicyEngine } from "./policy/PolicyEngine.js";

export type * from "./types/intent.js";
export type {
  KillSwitchState,
  AllowLists,
  BudgetState,
  VelocityConfig,
  VelocityCounters,
  RecursionState,
  ToolLimitsState,
  State,
  StateHash,
  CanonicalState,
  ModuleStateCodec
} from "./types/state.js";
export type * from "./types/policy.js";
export type * from "./types/authorization.js";