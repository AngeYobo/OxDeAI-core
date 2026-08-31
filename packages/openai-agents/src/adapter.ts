// SPDX-License-Identifier: Apache-2.0
import { OxDeAIGuard } from "@oxdeai/guard";
import type { ProposedAction } from "@oxdeai/guard";
import type { OpenAIAgentsToolCall, OpenAIAgentsGuardConfig, OpenAIAgentsGuardFn } from "./types.js";

/**
 * Convert an OpenAI Agents SDK tool call into an OxDeAI `ProposedAction`.
 *
 * - `name`                ← toolCall.name
 * - `args`                ← toolCall.input   (OpenAI Agents SDK uses `input`, not `args`)
 * - `context.agent_id`   ← config.agentId   (injected - tool calls carry no agent identity)
 * - `context.intent_id`  ← toolCall.call_id (when present; OpenAI uses `call_id`, not `id`)
 * - `estimatedCost`       ← toolCall.estimatedCost
 * - `resourceType`        ← toolCall.resourceType
 * - `timestampSeconds`    ← toolCall.timestampSeconds ?? now
 */
function toProposedAction(toolCall: OpenAIAgentsToolCall, agentId: string): ProposedAction {
  return {
    name: toolCall.name,
    args: toolCall.input,
    estimatedCost: toolCall.estimatedCost,
    resourceType: toolCall.resourceType,
    timestampSeconds: toolCall.timestampSeconds ?? Math.floor(Date.now() / 1000),
    context: {
      agent_id: agentId,
      ...(toolCall.call_id !== undefined ? { intent_id: toolCall.call_id } : {}),
    },
  };
}

/**
 * createOpenAIAgentsGuard - thin OpenAI Agents SDK binding for `@oxdeai/guard`.
 *
 * Returns a guard function that accepts an OpenAI Agents SDK tool call and an
 * execute callback. All authorization logic is delegated to `@oxdeai/guard` -
 * this adapter only handles the ToolCall → ProposedAction translation.
 *
 * @example
 * ```ts
 * import { createOpenAIAgentsGuard } from "@oxdeai/openai-agents";
 *
 * const guard = createOpenAIAgentsGuard({ engine, getState, setState, agentId: "my-agent" });
 *
 * const result = await guard(toolCall, () => executeTool(toolCall));
 * ```
 */
export function createOpenAIAgentsGuard(config: OpenAIAgentsGuardConfig): OpenAIAgentsGuardFn {
  const guard = OxDeAIGuard({
    engine: config.engine,
    getState: config.getState,
    setState: config.setState,
    mapActionToIntent: config.mapActionToIntent,
    beforeExecute: config.beforeExecute,
    onDecision: config.onDecision,
    onBoundaryEvent: config.onBoundaryEvent,
    expectedAudience: config.agentId,
    trustedKeySets: config.trustedKeySets,
    replayStore: config.replayStore,
    computeStateHash: config.computeStateHash,
  });

  return async function openAIAgentsGuard<T>(
    toolCall: OpenAIAgentsToolCall,
    execute: () => Promise<T>
  ): Promise<T> {
    const action = toProposedAction(toolCall, config.agentId);
    return guard(action, execute) as Promise<T>;
  };
}
