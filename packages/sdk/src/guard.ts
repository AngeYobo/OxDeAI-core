// SPDX-License-Identifier: Apache-2.0
import type { Intent, PolicyEngine, State, Authorization, AuthorizationV1 } from "@oxdeai/core";
import type { AuditAdapter, ClockAdapter, MaybePromise, StateAdapter, IntentBuilderInput } from "./types.js";
import { buildIntent } from "./builders.js";

export type GuardDecision =
  | { decision: "ALLOW"; reasons: []; authorization: AuthorizationV1 }
  | { decision: "DENY"; reasons: string[] };

export type GuardAllowResult<T> = {
  output: GuardDecision & { decision: "ALLOW"; reasons: []; authorization: AuthorizationV1 };
  intent: Intent;
  state: State;
  auditEvents: unknown[];
  executed: true;
  executionResult: T;
};

export type GuardDenyResult = {
  output: GuardDecision & { decision: "DENY"; reasons: string[] };
  intent: Intent;
  state: State;
  auditEvents: unknown[];
  executed: false;
};

export type GuardResult<T> = GuardAllowResult<T> | GuardDenyResult;

export type GuardInputIntent = Intent | IntentBuilderInput;

export type GuardOptions = {
  engine: PolicyEngine;
  stateAdapter: StateAdapter;
  auditAdapter?: AuditAdapter;
  clock?: ClockAdapter;
  mode?: "fail-fast" | "collect-all";
  /**
   * Engine-level HMAC binding check between the issued intent and authorization.
   * This is the PDP's own internal consistency check — distinct from PEP-side
   * cryptographic signature verification via `verifyAuthorization` from @oxdeai/core.
   * Defaults to true. Set to false only in test scenarios.
   */
  verifyAuthorization?: boolean;
};

type GuardExecuteContext = {
  intent: Intent;
  authorization: AuthorizationV1;
  state: State;
};

function collectNewEvents(engine: PolicyEngine, cursor: number): { nextCursor: number; events: unknown[] } {
  const all = engine.audit.snapshot() as unknown[];
  return { nextCursor: all.length, events: all.slice(cursor) };
}

function isIntent(value: GuardInputIntent): value is Intent {
  return (
    typeof (value as Intent).intent_id === "string" &&
    typeof (value as Intent).agent_id === "string" &&
    typeof (value as Intent).action_type === "string" &&
    typeof (value as Intent).signature === "string"
  );
}

export type GuardFn = <T>(
  input: GuardInputIntent,
  execute: (ctx: GuardExecuteContext) => MaybePromise<T>
) => Promise<GuardResult<T>>;

/**
 * Creates a guard that evaluates intents against policy and executes the callback
 * only when the decision is ALLOW (PDP + inline PEP path).
 *
 * This is the issuing side of the authorization boundary: it evaluates policy and
 * produces authorizations. For relying-party (PEP) verification of artifacts issued
 * by an external party, use `createVerifier` with explicit `trustedKeySets` instead.
 */
export function createGuard(opts: GuardOptions): GuardFn {
  const clock = opts.clock ?? { now: () => Math.floor(Date.now() / 1000) };
  let auditCursor = 0;

  return async function guard<T>(
    input: GuardInputIntent,
    execute: (ctx: GuardExecuteContext) => MaybePromise<T>
  ): Promise<GuardResult<T>> {
    const state = await opts.stateAdapter.load();
    // Single clock sample, reused for both the timestamp fallback below and
    // evaluationTime — the trusted-time freshness gate requires evaluationTime
    // to be sampled exactly once per evaluation (spec §2.1), and clock is the
    // same trusted-context boundary already responsible for the timestamp
    // fallback. Never derived from intent.timestamp itself (which may be
    // attacker-supplied). Note: clock defaults to Date.now()/1000 unless the
    // caller supplies an independent ClockAdapter; an explicitly supplied
    // value here is not necessarily independently trusted time.
    const evaluationTime = clock.now();
    const intent: Intent = isIntent(input)
      ? ({
          ...input,
          timestamp: input.timestamp === 0 ? evaluationTime : input.timestamp,
        } as Intent)
      : buildIntent({
          ...input,
          timestamp: input.timestamp ?? evaluationTime,
        });

    const out = opts.engine.evaluatePure(intent, state, evaluationTime, { mode: opts.mode ?? "fail-fast" });
    const emitted = collectNewEvents(opts.engine, auditCursor);
    auditCursor = emitted.nextCursor;

    if (opts.auditAdapter) await opts.auditAdapter.append(emitted.events);

    if (out.decision === "DENY") {
      return {
        output: { decision: "DENY", reasons: out.reasons },
        intent,
        state,
        auditEvents: emitted.events,
        executed: false,
      };
    }

    if (!out.authorization || !out.nextState) {
      return {
        output: { decision: "DENY", reasons: ["PEP_INVARIANT_VIOLATION"] },
        intent,
        state,
        auditEvents: emitted.events,
        executed: false,
      };
    }

    if (opts.verifyAuthorization !== false) {
      // Cast as Authorization: runtime object retains internal engine fields even
      // though the TypeScript type was narrowed to AuthorizationV1 at the evaluatePure boundary.
      // Verifier time is the single trusted `evaluationTime` sample taken above, never
      // intent.timestamp — that value is attacker-supplied, so reading it as "now" would
      // let the intent decide whether its own authorization has expired.
      const authCheck = opts.engine.verifyAuthorization(intent, out.authorization as Authorization, out.nextState, evaluationTime);
      if (!authCheck.valid) {
        return {
          output: { decision: "DENY", reasons: [`AUTH_INVALID:${authCheck.reason ?? "unknown"}`] },
          intent,
          state,
          auditEvents: emitted.events,
          executed: false,
        };
      }
    }

    const executionResult = await execute({
      intent,
      authorization: out.authorization,
      state: out.nextState,
    });
    await opts.stateAdapter.save(out.nextState);

    return {
      output: { decision: "ALLOW", reasons: [], authorization: out.authorization },
      intent,
      state: out.nextState,
      auditEvents: emitted.events,
      executed: true,
      executionResult,
    };
  };
}
