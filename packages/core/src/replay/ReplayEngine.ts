// SPDX-License-Identifier: Apache-2.0
import type { AuditEntry } from "../audit/AuditLog.js";
import { PolicyEngine } from "../policy/PolicyEngine.js";
import type { EngineEvalOptions, EvaluatePureOutput } from "../policy/PolicyEngine.js";
import type { Intent } from "../types/intent.js";
import type { State } from "../types/state.js";
import type { VerifyOptions, VerifyResult } from "./verify.js";
import { verifyReplayEvents } from "./verify.js";

/** @public */
export type ReplayResult = {
  outputs: EvaluatePureOutput[];
  finalState: State;
  allDeterministic: boolean;
};

/** @public */
export type AuditReplayResult = {
  invariantViolations: string[];
};

/** @public */
export class ReplayEngine {
  private readonly engine: PolicyEngine;

  constructor(engine: PolicyEngine) {
    this.engine = engine;
  }

  /**
   * `evaluationTime` accepts one explicit trusted-time value as a temporary
   * deterministic compatibility model required to thread the new engine
   * input (docs/spec/core/trusted-time-v1.md §2.1). It does NOT guarantee
   * faithful historical replay: every intent in `intents` is evaluated
   * against this single, fixed `evaluationTime`, regardless of when it was
   * originally decided. Replayed decisions may therefore differ from the
   * original decisions - including by returning `INTENT_STALE` - when the
   * log spans more than `maxIntentAgeSeconds` relative to the supplied
   * evaluation instant.
   *
   * Historical trusted-time fidelity remains unsupported until each
   * original `evaluation_time` is captured in execution evidence and can be
   * supplied per intent (deferred follow-up).
   */
  replay(initialState: State, intents: Intent[], evaluationTime: number, opts?: EngineEvalOptions): ReplayResult {
    let state = structuredClone(initialState);
    const outputs: EvaluatePureOutput[] = [];

    for (const intent of intents) {
      const out = this.engine.evaluatePure(intent, state, evaluationTime, opts);
      outputs.push(out);
      if (out.decision === "ALLOW") state = out.nextState;
    }

    return { outputs, finalState: state, allDeterministic: true };
  }

  replayFromAudit(
    initialState: State,
    _audit: readonly AuditEntry[],
    intents: Intent[],
    evaluationTime: number,
    opts?: EngineEvalOptions
  ): ReplayResult {
    return this.replay(initialState, intents, evaluationTime, opts);
  }

  static verify(events: readonly AuditEntry[], opts?: VerifyOptions): VerifyResult {
    return verifyReplayEvents(events, opts);
  }

  static replay(events: readonly AuditEntry[], opts?: { policyId?: string }): AuditReplayResult {
    const verified = verifyReplayEvents(events, {
      policyId: opts?.policyId,
      mode: "best-effort"
    });
    const invariantViolations = verified.violations.map((v) =>
      v.detail ? `${v.code}${v.at !== undefined ? `@${v.at}` : ""}: ${v.detail}` : `${v.code}${v.at !== undefined ? `@${v.at}` : ""}`
    );
    return { invariantViolations };
  }
}
