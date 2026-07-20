// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

function prune(events: Array<{ ts: number; tool?: string }>, cutoff: number): Array<{ ts: number; tool?: string }> {
  // deterministic prune: keep only events within window
  return events.filter((e) => e.ts >= cutoff);
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
export function ToolAmplificationModule(intent: Intent, state: State): PolicyResult {
  const agent = intent.agent_id;

  // Do not block RELEASE lifecycle (avoid deadlocks)
  const t = intent.type ?? "EXECUTE";
  if (t === "RELEASE") return { decision: "ALLOW", reasons: [] };

  // Trusted classification only — intent.tool_call is descriptive/compat
  // data and MUST NOT gate enforcement. See isRateLimitedToolCall above.
  if (!isRateLimitedToolCall(intent, state)) return { decision: "ALLOW", reasons: [] };

  const tl = state.tool_limits;
  if (!tl || typeof tl.window_seconds !== "number" || !tl.max_calls || !tl.calls) {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  const max = tl.max_calls[agent];
  if (max === undefined) return { decision: "DENY", reasons: ["STATE_INVALID"] };

  const now = intent.timestamp;
  const cutoff = now - tl.window_seconds;

  const current = tl.calls[agent] ?? [];
  const pruned = prune(current, cutoff);

  // total count check
  if (pruned.length + 1 > max) {
    return { decision: "DENY", reasons: ["TOOL_CALL_LIMIT_EXCEEDED"] };
  }

  // optional per-tool cap check
  const toolName = intent.tool;
  if (toolName && tl.max_calls_by_tool?.[agent]?.[toolName] !== undefined) {
    const toolMax = tl.max_calls_by_tool[agent][toolName];
    const toolCount = pruned.reduce((acc, e) => (e.tool === toolName ? acc + 1 : acc), 0);
    if (toolCount + 1 > toolMax) {
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
