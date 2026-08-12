// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "@oxdeai/core";
import { OxDeAIGuard } from "./guard.js";
import { defaultNormalizeAction } from "./normalizeAction.js";
import { createInMemoryReplayStore } from "./replayStore.js";
import { OxDeAIAuthorizationError } from "./errors.js";
import { isTrustedExecutionContext, type TrustedExecutionContext } from "./trustedContext.js";
import { reconcileWithTrustedContext, type ProvenanceRecord } from "./provenance.js";
import type { OxDeAIGuardConfig, ProposedAction, GuardCallOptions } from "./types.js";

/**
 * Tier 1 secure guard entry point.
 *
 * The secure path differs from {@link OxDeAIGuard} in exactly one respect: how
 * the evaluated intent's provenance is established. Everything after that —
 * state read, evaluation, authorization verification, replay consumption,
 * intent/state hash binding, CAS, execution ordering — is the SAME enforcement
 * body, reached by delegating to `OxDeAIGuard` rather than by reimplementing
 * it. Two entry points that share one body cannot drift apart.
 *
 * ```text
 * authenticate                       (caller, before this function)
 * → resolve trusted context          (createTrustedExecutionContext)
 * → normalize proposal → reconcile   (here; conflicts fail closed)
 * → read state → evaluate → verify → CAS → execute   (shared body)
 * ```
 *
 * Trusted context is a separate positional argument and never a field on
 * {@link ProposedAction}: there is no place to put it in the request payload,
 * so "trusted context is not accepted from request JSON" holds structurally
 * rather than by convention.
 *
 * ⚠️ Only this path, or an integration independently enforcing the same
 * boundary, may claim Tier 1 evaluator-input provenance. `OxDeAIGuard` remains
 * available and unchanged, and carries no such guarantee.
 *
 * SCOPE — this entry point establishes trusted *evaluator inputs* only. It does
 * NOT make state or policy authoritative: `getState` / `setState` and the
 * engine's policy configuration are still supplied by the deployment. An
 * authoritative versioned StateProvider and PolicyProvider are separate work.
 *
 * @public
 */
export function createSecureGuard(config: OxDeAIGuardConfig) {
  const baseNormalize: (action: ProposedAction) => Intent =
    config.mapActionToIntent ?? defaultNormalizeAction;

  // Resolve the replay store ONCE. The guard closure is rebuilt per call so
  // that each call's provenance capture is isolated, and a per-call default
  // store would otherwise give every call a fresh replay namespace — silently
  // disabling replay protection across calls.
  const replayStore = config.replayStore ?? createInMemoryReplayStore();

  return async function secureGuard(
    trustedContext: TrustedExecutionContext,
    action: ProposedAction,
    execute: () => Promise<unknown>,
    opts?: GuardCallOptions
  ): Promise<unknown> {
    if (!isTrustedExecutionContext(trustedContext)) {
      throw new OxDeAIAuthorizationError(
        "Secure guard requires a TrustedExecutionContext built by createTrustedExecutionContext(). " +
          "A plain object — including one deserialized from request JSON — is not accepted. Execution blocked."
      );
    }

    let provenance: ProvenanceRecord | undefined;

    const secureConfig: OxDeAIGuardConfig = {
      ...config,
      replayStore,
      // Reconciliation runs on the OUTPUT of the deployment's normalizer, so a
      // custom mapActionToIntent cannot overwrite a trusted premise.
      mapActionToIntent: (a: ProposedAction): Intent => {
        const proposed = baseNormalize(a);
        const reconciled = reconcileWithTrustedContext(proposed, trustedContext, a.context);
        provenance = reconciled.provenance;
        return reconciled.intent;
      },
      onDecision: config.onDecision
        ? (record) => config.onDecision!({ ...record, ...(provenance ? { provenance } : {}) })
        : undefined,
    };

    return OxDeAIGuard(secureConfig)(action, execute, opts);
  };
}
