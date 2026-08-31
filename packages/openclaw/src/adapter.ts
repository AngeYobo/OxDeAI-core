// SPDX-License-Identifier: Apache-2.0
import { OxDeAIGuard } from "@oxdeai/guard";
import type { ProposedAction } from "@oxdeai/guard";
import type { OpenClawAction, OpenClawGuardConfig, OpenClawGuardFn } from "./types.js";

/**
 * Convert an OpenClaw action into an OxDeAI `ProposedAction`.
 *
 * - `name`                    ← action.name
 * - `args`                    ← action.args
 * - `context.agent_id`       ← config.agentId   (injected - action calls carry no agent identity)
 * - `context.intent_id`      ← action.step_id   (when present; step_id is the per-action identifier)
 * - `context.workflow_id`    ← action.workflow_id (when present; passed as extra context)
 * - `estimatedCost`           ← action.estimatedCost
 * - `resourceType`            ← action.resourceType
 * - `timestampSeconds`        ← action.timestampSeconds ?? now
 */
function toProposedAction(action: OpenClawAction, agentId: string): ProposedAction {
  return {
    name: action.name,
    args: action.args,
    estimatedCost: action.estimatedCost,
    resourceType: action.resourceType,
    timestampSeconds: action.timestampSeconds ?? Math.floor(Date.now() / 1000),
    context: {
      agent_id: agentId,
      ...(action.step_id !== undefined ? { intent_id: action.step_id } : {}),
      ...(action.workflow_id !== undefined ? { workflow_id: action.workflow_id } : {}),
    },
  };
}

/**
 * createOpenClawGuard - thin OpenClaw binding for `@oxdeai/guard`.
 *
 * Returns a guard function that accepts an OpenClaw action and an execute
 * callback. All authorization logic is delegated to `@oxdeai/guard` - this
 * adapter only handles the OpenClaw Action → ProposedAction translation.
 *
 * @example
 * ```ts
 * import { createOpenClawGuard } from "@oxdeai/openclaw";
 *
 * const guard = createOpenClawGuard({ engine, getState, setState, agentId: "my-agent" });
 *
 * const result = await guard(action, () => executeAction(action));
 * ```
 */
export function createOpenClawGuard(config: OpenClawGuardConfig): OpenClawGuardFn {
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

  return async function openClawGuard<T>(
    action: OpenClawAction,
    execute: () => Promise<T>
  ): Promise<T> {
    const proposed = toProposedAction(action, config.agentId);
    return guard(proposed, execute) as Promise<T>;
  };
}
