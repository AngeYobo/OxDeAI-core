// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyEvaluationContext, PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isValidEvent(value: unknown): value is { ts: number; tool?: string } {
  if (!isRecord(value) || !isNonNegativeSafeInteger(value.ts)) return false;
  return value.tool === undefined || (typeof value.tool === "string" && value.tool.length > 0);
}

/**
 * Trusted tool-call classifier.
 *
 * `intent.tool_call` is a self-declared, agent-controlled field and MUST NOT
 * influence this decision (an agent can omit or falsify it to bypass
 * enforcement). Classification instead follows the trusted action
 * discriminator (`EXECUTE`) plus policy-controlled tool configuration in
 * `state.tool_limits`, resolved via the agent-supplied `intent.tool` used
 * only as a lookup key — the same pattern AllowlistModule uses to resolve
 * `intent.action_type`/`intent.target` against `state.allowlists`. A bare
 * non-empty `tool` string is never sufficient on its own; it must also
 * resolve against trusted state.
 *
 * @public
 */
export function isRateLimitedToolCall(intent: Intent, state: State): boolean {
  const t = intent.type ?? "EXECUTE";
  if (t !== "EXECUTE") return false;

  const tool = intent.tool;
  if (typeof tool !== "string" || tool.length === 0) return false;

  const tl = state.tool_limits;
  if (!tl) return false;

  const agent = intent.agent_id;
  if (tl.max_calls_by_tool?.[agent]?.[tool] !== undefined) return true;
  return tl.max_calls?.[agent] !== undefined;
}

/** @public */
export function ToolAmplificationModule(
  intent: Intent,
  state: State,
  context: PolicyEvaluationContext,
): PolicyResult {
  const agent = intent.agent_id;

  // Do not block RELEASE lifecycle (avoid deadlocks)
  const t = intent.type ?? "EXECUTE";
  if (t === "RELEASE") return { decision: "ALLOW", reasons: [] };

  const toolName = intent.tool;
  if (typeof toolName !== "string" || toolName.length === 0) {
    return { decision: "ALLOW", reasons: [] };
  }

  const tl = state.tool_limits;
  if (
    !isRecord(tl) ||
    !Number.isSafeInteger(tl.window_seconds) ||
    (tl.window_seconds as number) <= 0 ||
    !isRecord(tl.max_calls) ||
    !isRecord(tl.calls) ||
    (tl.max_calls_by_tool !== undefined && !isRecord(tl.max_calls_by_tool))
  ) {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  const max = tl.max_calls[agent];
  if (!isNonNegativeSafeInteger(max)) return { decision: "DENY", reasons: ["STATE_INVALID"] };

  const configuredToolLimits = tl.max_calls_by_tool?.[agent];
  if (configuredToolLimits !== undefined && !isRecord(configuredToolLimits)) {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  for (const configuredMax of Object.values(configuredToolLimits ?? {})) {
    // A per-tool cap may tighten, but cannot contradict, the aggregate cap.
    if (!isNonNegativeSafeInteger(configuredMax) || configuredMax > max) {
      return { decision: "DENY", reasons: ["STATE_INVALID"] };
    }
  }

  // Trusted classification only — intent.tool_call is descriptive/compat
  // data and MUST NOT gate enforcement. See isRateLimitedToolCall above.
  if (!isRateLimitedToolCall(intent, state)) return { decision: "ALLOW", reasons: [] };

  const now = context.evaluationTime;
  const currentValue = tl.calls[agent];
  if (currentValue !== undefined && !Array.isArray(currentValue)) {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }
  const current = currentValue ?? [];
  if (!current.every(isValidEvent) || current.length > max) {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }
  for (const event of current) {
    if (event.ts > now) return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  for (const [tool, configuredMax] of Object.entries(configuredToolLimits ?? {})) {
    if (!isNonNegativeSafeInteger(configuredMax)) {
      return { decision: "DENY", reasons: ["STATE_INVALID"] };
    }
    const persistedCount = current.reduce((count, event) => count + (event.tool === tool ? 1 : 0), 0);
    if (persistedCount > configuredMax) return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  // Subtraction is exact and safe: both operands are non-negative safe
  // integers and the backward-time case was rejected above. Exact-boundary
  // events expire, matching the trusted velocity-window rule.
  const pruned = current.filter((event) => now - event.ts < tl.window_seconds);

  // total count check
  if (pruned.length >= max) {
    return { decision: "DENY", reasons: ["TOOL_CALL_LIMIT_EXCEEDED"] };
  }

  // optional per-tool cap check
  if (toolName && tl.max_calls_by_tool?.[agent]?.[toolName] !== undefined) {
    const toolMax = configuredToolLimits?.[toolName];
    if (toolMax === undefined) return { decision: "DENY", reasons: ["STATE_INVALID"] };
    const toolCount = pruned.reduce((acc, e) => (e.tool === toolName ? acc + 1 : acc), 0);
    if (toolCount >= toolMax) {
      return { decision: "DENY", reasons: ["TOOL_CALL_LIMIT_EXCEEDED"] };
    }
  }

  // propose delta: prune + append
  const nextEvents = [...pruned, { ts: now, tool: toolName }];

  return {
    decision: "ALLOW",
    reasons: [],
    stateDelta: {
      tool_limits: {
        ...tl,
        calls: {
          ...tl.calls,
          [agent]: nextEvents
        }
      }
    }
  };
}

/** @public */
export const ToolAmplificationModuleCodec = statelessModuleCodec("ToolAmplificationModule");
