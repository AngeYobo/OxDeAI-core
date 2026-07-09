// SPDX-License-Identifier: Apache-2.0
import type { State } from "../types/state.js";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/**
 * isRuntimeState(): structural validation for the runtime `State` shape.
 * Validates presence of required containers and that fixed numeric config
 * leaves are finite numbers (not merely `typeof === "number"`, which would
 * still accept NaN). Per-agent leaves are validated separately by
 * validateNumericLeaves() since they depend on the evaluated agent_id.
 */
export function isRuntimeState(state: unknown): state is State {
  if (!isObject(state)) return false;

  if (typeof state.policy_version !== "string") return false;
  if (typeof state.period_id !== "string") return false;

  const requiredTop = [
    "period_id",
    "kill_switch",
    "allowlists",
    "budget",
    "max_amount_per_action",
    "velocity",
    "replay",
    "concurrency",
    "recursion",
    "tool_limits"
  ];
  for (const k of requiredTop) {
    if (!(k in state)) return false;
  }

  const ks = state.kill_switch;
  if (!isObject(ks) || typeof ks.global !== "boolean" || !isObject(ks.agents)) return false;

  const al = state.allowlists;
  if (!isObject(al)) return false;

  const budget = state.budget;
  if (!isObject(budget) || !isObject(budget.budget_limit) || !isObject(budget.spent_in_period)) {
    return false;
  }

  const caps = state.max_amount_per_action;
  if (!isObject(caps)) return false;

  const vel = state.velocity;
  if (!isObject(vel) || !isObject(vel.config) || !isObject(vel.counters)) return false;
  if (!Number.isFinite(vel.config.window_seconds) || !Number.isFinite(vel.config.max_actions)) {
    return false;
  }

  const rp = state.replay;
  if (!isObject(rp) || !isObject(rp.nonces)) return false;
  if (!Number.isFinite(rp.window_seconds) || !Number.isFinite(rp.max_nonces_per_agent)) {
    return false;
  }

  const cc = state.concurrency;
  if (!isObject(cc) || !isObject(cc.max_concurrent) || !isObject(cc.active) || !isObject(cc.active_auths)) {
    return false;
  }

  const rc = state.recursion;
  if (!isObject(rc) || !isObject(rc.max_depth)) return false;

  const tl = state.tool_limits;
  if (!isObject(tl) || !isObject(tl.max_calls) || !isObject(tl.calls)) return false;
  if (!Number.isFinite(tl.window_seconds)) return false;

  return true;
}

/**
 * validateNumericLeaves(): per-agent leaf validation for the evaluated
 * agentId. Runs after isRuntimeState() has confirmed containers exist.
 * bigint leaves are checked with `typeof === "bigint"` (Number.isFinite does
 * not apply to bigint); numeric leaves are checked with Number.isFinite so a
 * corrupted NaN or non-numeric value fails closed instead of silently
 * comparing incorrectly.
 */
export function validateNumericLeaves(
  state: State,
  agentId: string
): { ok: true } | { ok: false; field: string } {
  const budgetLimit = state.budget.budget_limit[agentId];
  if (budgetLimit === undefined || typeof budgetLimit !== "bigint") {
    return { ok: false, field: "budget.budget_limit" };
  }

  const spent = state.budget.spent_in_period[agentId];
  if (spent !== undefined && typeof spent !== "bigint") {
    return { ok: false, field: "budget.spent_in_period" };
  }

  const cap = state.max_amount_per_action[agentId];
  if (cap === undefined || typeof cap !== "bigint") {
    return { ok: false, field: "max_amount_per_action" };
  }

  const maxConcurrent = state.concurrency.max_concurrent[agentId];
  if (maxConcurrent === undefined || !Number.isFinite(maxConcurrent)) {
    return { ok: false, field: "concurrency.max_concurrent" };
  }

  const maxDepth = state.recursion.max_depth[agentId];
  if (maxDepth === undefined || !Number.isFinite(maxDepth)) {
    return { ok: false, field: "recursion.max_depth" };
  }

  const maxCalls = state.tool_limits.max_calls[agentId];
  if (maxCalls === undefined || !Number.isFinite(maxCalls)) {
    return { ok: false, field: "tool_limits.max_calls" };
  }

  return { ok: true };
}
