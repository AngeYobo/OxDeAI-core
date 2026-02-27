import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

function prune(events: Array<{ ts: number; tool?: string }>, cutoff: number): Array<{ ts: number; tool?: string }> {
  // deterministic prune: keep only events within window
  return events.filter((e) => e.ts >= cutoff);
}

export function ToolAmplificationModule(intent: Intent, state: State): PolicyResult {
  const agent = intent.agent_id;

  // Do not block RELEASE lifecycle (avoid deadlocks)
  const t = intent.type ?? "EXECUTE";
  if (t === "RELEASE") return { decision: "ALLOW", reasons: [] };

  // Explicit opt-in: only enforce for tool calls
  if (intent.tool_call !== true) return { decision: "ALLOW", reasons: [] };

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

export const ToolAmplificationModuleCodec = statelessModuleCodec("ToolAmplificationModule");
