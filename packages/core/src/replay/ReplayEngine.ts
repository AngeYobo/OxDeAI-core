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

  replay(initialState: State, intents: Intent[], opts?: EngineEvalOptions): ReplayResult {
    let state = structuredClone(initialState);
    const outputs: EvaluatePureOutput[] = [];

    for (const intent of intents) {
      const out = this.engine.evaluatePure(intent, state, opts);
      outputs.push(out);
      if (out.decision === "ALLOW") state = out.nextState;
    }

    return { outputs, finalState: state, allDeterministic: true };
  }

  replayFromAudit(initialState: State, _audit: readonly AuditEntry[], intents: Intent[], opts?: EngineEvalOptions): ReplayResult {
    return this.replay(initialState, intents, opts);
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
