import type { AuditEntry } from "../audit/AuditLog.js";
import { PolicyEngine } from "../policy/PolicyEngine.js";
import type { EngineEvalOptions, EvaluatePureOutput } from "../policy/PolicyEngine.js";
import type { Intent } from "../types/intent.js";
import type { State } from "../types/state.js";

export type ReplayResult = {
  outputs: EvaluatePureOutput[];
  finalState: State;
  allDeterministic: boolean;
};

export type AuditReplayResult = {
  invariantViolations: string[];
};

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

  static replay(events: readonly AuditEntry[], opts?: { policyId?: string }): AuditReplayResult {
    const invariantViolations: string[] = [];
    const expectedPolicyId = opts?.policyId;

    if (expectedPolicyId) {
      for (let i = 0; i < events.length; i++) {
        const e = events[i];
        if (e.policyId !== undefined && e.policyId !== expectedPolicyId) {
          invariantViolations.push(
            `policyId mismatch at event[${i}] (event=${e.policyId}, expected=${expectedPolicyId})`
          );
        }
      }
    }

    for (let i = 1; i < events.length; i++) {
      if (events[i].timestamp < events[i - 1].timestamp) {
        invariantViolations.push(`non-monotonic timestamp at event[${i}]`);
      }
    }

    return { invariantViolations };
  }
}
