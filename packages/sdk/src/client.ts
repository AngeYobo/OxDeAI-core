// SPDX-License-Identifier: Apache-2.0
import {
  PolicyEngine,
  encodeCanonicalState,
  encodeEnvelope,
  verifyAuditEvents,
  verifyEnvelope,
  verifySnapshot
} from "@oxdeai/core";
import type { Authorization, AuthorizationV1, Intent } from "@oxdeai/core";

import type {
  AuditAdapter,
  ClockAdapter,
  EvaluateAndCommitResult,
  EvaluateDecision,
  StateAdapter,
  VerifyBundleResult
} from "./types.js";

type ClientOptions = {
  engine: PolicyEngine;
  stateAdapter: StateAdapter;
  auditAdapter?: AuditAdapter;
  clock?: ClockAdapter;
};

type EvaluateInput = Omit<Intent, "timestamp"> & { timestamp?: number };

function collectNewEvents(engine: PolicyEngine, cursor: number): { nextCursor: number; events: unknown[] } {
  const all = engine.audit.snapshot() as unknown[];
  const events = all.slice(cursor);
  return { nextCursor: all.length, events };
}

export class OxDeAIClient {
  private readonly engine: PolicyEngine;
  private readonly stateAdapter: StateAdapter;
  private readonly auditAdapter?: AuditAdapter;
  private readonly clock: ClockAdapter;
  private auditCursor = 0;

  constructor(opts: ClientOptions) {
    this.engine = opts.engine;
    this.stateAdapter = opts.stateAdapter;
    this.auditAdapter = opts.auditAdapter;
    this.clock = opts.clock ?? { now: () => Math.floor(Date.now() / 1000) };
  }

  async evaluateAndCommit(input: EvaluateInput): Promise<EvaluateAndCommitResult> {
    const state = await this.stateAdapter.load();
    // Single clock sample, reused for both the timestamp fallback below and
    // evaluationTime — the trusted-time freshness gate requires evaluationTime
    // to be sampled exactly once per evaluation (spec §2.1), and this.clock is
    // the same trusted-context boundary already responsible for the timestamp
    // fallback. Never derived from intent.timestamp itself (which may be
    // attacker-supplied via `input.timestamp`). Note: this.clock defaults to
    // Date.now()/1000 unless the caller supplies an independent ClockAdapter;
    // an explicitly supplied value here is not necessarily independently
    // trusted time.
    const evaluationTime = this.clock.now();
    const resolvedTimestamp = input.timestamp === undefined || input.timestamp === 0
      ? evaluationTime
      : input.timestamp;
    const intent: Intent = {
      ...input,
      timestamp: resolvedTimestamp
    } as Intent;

    const out = this.engine.evaluatePure(intent, state, evaluationTime, { mode: "fail-fast" });
    const emitted = collectNewEvents(this.engine, this.auditCursor);
    this.auditCursor = emitted.nextCursor;

    if (this.auditAdapter) await this.auditAdapter.append(emitted.events);

    if (out.decision === "ALLOW") {
      await this.stateAdapter.save(out.nextState);
      const output: EvaluateDecision = {
        decision: "ALLOW",
        reasons: [],
        authorization: out.authorization
      };
      return { output, state: out.nextState, auditEvents: emitted.events };
    }

    const output: EvaluateDecision = {
      decision: "DENY",
      reasons: out.reasons
    };
    return { output, state, auditEvents: emitted.events };
  }

  /**
   * Verifies an authorization against a trusted verification time.
   *
   * Verifier time is taken from the client's trusted clock boundary, or from an
   * explicit `verificationTime` when the caller already holds one from the trusted
   * execution boundary. It is never derived from `intent.timestamp`: that value is
   * attacker-supplied and is hash-bound into the authorization at issuance, so using
   * it as "now" pins the expiry comparison to issuance time and the authorization
   * never expires.
   *
   * ⚠️ Inherits the LIMITED SCOPE of `PolicyEngine.verifyAuthorization` — it
   * authenticates only the engine-HMAC field subset. Relying parties enforcing an
   * authorization issued by an external party must use the strict standalone
   * verifier with explicit `trustedKeySets` instead.
   */
  async verifyAuthorization(
    intent: Intent,
    authorization: AuthorizationV1,
    opts?: { verificationTime?: number }
  ): Promise<{ valid: boolean; reason?: string }> {
    const state = await this.stateAdapter.load();
    const verificationTime = opts?.verificationTime ?? this.clock.now();
    // Cast as Authorization: internal engine.verifyAuthorization() uses legacy fields
    // (engine_signature, state_snapshot_hash) for HMAC binding verification.
    // Authorization objects returned by evaluatePure() retain these at runtime.
    const result = this.engine.verifyAuthorization(intent, authorization as Authorization, state, verificationTime);
    return result.valid ? { valid: true } : { valid: false, reason: result.reason };
  }

  /**
   * Verifies the current in-memory snapshot, audit log, and envelope.
   *
   * Defaults to `mode: "best-effort"` — structural checks only, no `trustedKeySets`
   * required. Passing `mode: "strict"` additionally requires a signed envelope with a
   * STATE_CHECKPOINT; without `trustedKeySets` it will return `TRUSTED_KEYSETS_REQUIRED`.
   *
   * For PEP-side trust verification of artifacts issued by an external party, use
   * `createVerifier` with explicit `trustedKeySets` rather than this method.
   */
  async verifyCurrentArtifacts(opts?: { mode?: "strict" | "best-effort" }): Promise<VerifyBundleResult> {
    const state = await this.stateAdapter.load();
    const snapshotBytes = encodeCanonicalState(this.engine.exportState(state));
    const snapshot = verifySnapshot(snapshotBytes);

    const allEvents = this.engine.audit.snapshot();
    const audit = verifyAuditEvents(allEvents as Parameters<typeof verifyAuditEvents>[0], {
      mode: opts?.mode ?? "best-effort"
    });

    const envelopeBytes = encodeEnvelope({
      formatVersion: 1,
      snapshot: snapshotBytes,
      events: allEvents as any
    });
    const envelope = verifyEnvelope(envelopeBytes, { mode: opts?.mode ?? "best-effort" });
    return { snapshot, audit, envelope };
  }
}
