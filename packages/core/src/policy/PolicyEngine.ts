// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import type { Intent } from "../types/intent.js";
import type { State, CanonicalState } from "../types/state.js";
import type { Authorization, AuthorizationV1 } from "../types/authorization.js";
import type { ReasonCode, PolicyModule } from "../types/policy.js";

import { canonicalJson, intentHash, sha256HexFromJson } from "../crypto/hashes.js";
import { engineSignHmac } from "../crypto/sign.js";
import { engineVerifyHmac } from "../crypto/verify.js";
import { SIGNING_DOMAINS, signEd25519, signHmacDomain } from "../crypto/signatures.js";
import { deepMerge } from "../utils/deepMerge.js";
import { runDecisionModules } from "./decision/index.js";

import { HashChainedLog } from "../audit/HashChainedLog.js";
import type { AuditEvent } from "../audit/AuditLog.js";
import { KillSwitchModule } from "./modules/KillSwitchModule.js";
import { AllowlistModule } from "./modules/AllowlistModule.js";
import { BudgetModule } from "./modules/BudgetModule.js";
import { VelocityModule } from "./modules/VelocityModule.js";

import { ReplayModule } from "./modules/ReplayModule.js";
import { ConcurrencyModule } from "./modules/ConcurrencyModule.js";
import { RecursionDepthModule } from "./modules/RecursionDepthModule.js";
import { ToolAmplificationModule } from "./modules/ToolAmplificationModule.js";
import type { StateStore, AuditSink } from "../adapters/types.js";
import { stableStringify } from "../utils/stableStringify.js";
import { createCanonicalState, withModuleState } from "../snapshot/CanonicalState.js";
import { MODULE_CODECS } from "./modules/registry.js";

/** @public */
export type EngineEvalOptions = {
  mode?: "fail-fast" | "collect-all";
};

/** @public */
export type EvaluateOutput =
  | { decision: "ALLOW"; reasons: []; authorization: AuthorizationV1 }
  | { decision: "DENY"; reasons: ReasonCode[] };

/** @public */
export type EvaluatePureOutput =
  | { decision: "ALLOW"; reasons: []; authorization: AuthorizationV1; nextState: State }
  | { decision: "DENY"; reasons: ReasonCode[] };

/** @public */
export type SimulationResult = {
  outputs: EvaluatePureOutput[];
  finalState: State;
};

/** @public */
export type EngineOptions = {
  policy_version: string;
  engine_secret: string;
  authorization_ttl_seconds?: number;
  authorization_issuer?: string;
  authorization_audience?: string;
  /**
   * Algorithm used to sign emitted `AuthorizationV1` artifacts.
   *
   * Defaults to `"HMAC-SHA256"` for backward compatibility. **This default is
   * deprecated.** New deployments SHOULD set this to `"Ed25519"` and provide
   * `authorization_private_key_pem`. `"HMAC-SHA256"` will be removed as a valid
   * default in a future major release.
   *
   * @deprecated Pass `"Ed25519"` explicitly for all new integrations.
   */
  authorization_signing_alg?: "Ed25519" | "HMAC-SHA256";
  authorization_signing_kid?: string;
  authorization_private_key_pem?: string;
  deny_mode?: "collect-all" | "fail-fast";
  policyId?: string;
  strictDeterminism?: boolean;
  checkpoint_every_n_events?: number;
  stateStore?: StateStore;
  auditSink?: AuditSink;
  autoPersist?: boolean;
};

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

// Keep canonical snapshot hashes stable across host package managers/runners.
const ENGINE_VERSION = "unknown";

const RELEASE_MODULES: readonly PolicyModule[] = [
  { id: "KillSwitchModule", evaluate: KillSwitchModule, codec: MODULE_CODECS.KillSwitchModule },
  { id: "ReplayModule", evaluate: ReplayModule, codec: MODULE_CODECS.ReplayModule },
  { id: "ConcurrencyModule", evaluate: ConcurrencyModule, codec: MODULE_CODECS.ConcurrencyModule }
];

const EXECUTE_MODULES: readonly PolicyModule[] = [
  { id: "KillSwitchModule", evaluate: KillSwitchModule, codec: MODULE_CODECS.KillSwitchModule },
  { id: "AllowlistModule", evaluate: AllowlistModule, codec: MODULE_CODECS.AllowlistModule },
  { id: "ReplayModule", evaluate: ReplayModule, codec: MODULE_CODECS.ReplayModule },
  { id: "RecursionDepthModule", evaluate: RecursionDepthModule, codec: MODULE_CODECS.RecursionDepthModule },
  { id: "ConcurrencyModule", evaluate: ConcurrencyModule, codec: MODULE_CODECS.ConcurrencyModule },
  { id: "ToolAmplificationModule", evaluate: ToolAmplificationModule, codec: MODULE_CODECS.ToolAmplificationModule },
  { id: "BudgetModule", evaluate: BudgetModule, codec: MODULE_CODECS.BudgetModule },
  { id: "VelocityModule", evaluate: VelocityModule, codec: MODULE_CODECS.VelocityModule }
];

/** @public */
export class PolicyEngine {
  private readonly opts: EngineOptions;
  private currentState?: State;
  private auditEventCount = 0;
  // Adapter writes are sequenced here so evaluate/evaluatePure remain synchronous.
  private auditSinkChain: Promise<void> = Promise.resolve();
  private stateStoreChain: Promise<void> = Promise.resolve();
  private auditSinkError: unknown | null = null;
  private stateStoreError: unknown | null = null;
  public readonly audit: HashChainedLog = new HashChainedLog();

  constructor(opts: EngineOptions) {
    if (typeof opts.engine_secret !== "string" || opts.engine_secret.length < 32) {
      throw new Error(
        `engine_secret must be a string of at least 32 characters (got ${
          typeof opts.engine_secret === "string"
            ? `${opts.engine_secret.length} chars`
            : typeof opts.engine_secret
        })`
      );
    }
    this.opts = opts;
  }

  private authorizationTtlSeconds(): number {
    return this.opts.authorization_ttl_seconds ?? 60;
  }

  private authorizationIssuer(): string {
    return this.opts.authorization_issuer ?? "oxdeai.policy-engine";
  }

  private authorizationAudience(): string {
    return this.opts.authorization_audience ?? "oxdeai.relying-party";
  }

  private authorizationSigningAlg(): "Ed25519" | "HMAC-SHA256" {
    // Default is "HMAC-SHA256" for backward compatibility only.
    // New configurations should pass authorization_signing_alg: "Ed25519".
    return this.opts.authorization_signing_alg ?? "HMAC-SHA256";
  }

  private authorizationSigningKid(): string {
    return this.opts.authorization_signing_kid ?? (this.authorizationSigningAlg() === "Ed25519" ? "ed25519-default" : "hmac-default");
  }

  /**
   * validateState(): explicit runtime validation for fail-closed semantics.
   * Goal: structural corruption should return STATE_INVALID (not INTERNAL_ERROR).
   * Note: per-agent configuration is validated for the current intent.agent_id only.
   */
  private validateStateForIntent(state: unknown, intent: Intent): { ok: true } | { ok: false; reason: ReasonCode } {
    if (!isObject(state)) return { ok: false, reason: "STATE_INVALID" };

    // policy_version check is handled separately to keep reason specific
    if (!("policy_version" in state) || typeof (state as any).policy_version !== "string") {
      return { ok: false, reason: "STATE_INVALID" };
    }


    // Required top-level keys
    const requiredTop = [
      "period_id",
      "kill_switch",
      "allowlists",
      "budget",
      "max_amount_per_action",
      "velocity",
      "replay",
      "concurrency",
      "recursion",
      "tool_limits"
    ];
    for (const k of requiredTop) {
      if (!(k in state)) return { ok: false, reason: "STATE_INVALID" };
    }

    const ks = (state as any).kill_switch;
    if (!isObject(ks) || typeof ks.global !== "boolean" || !isObject(ks.agents)) {
      return { ok: false, reason: "STATE_INVALID" };
    }

    const al = (state as any).allowlists;
    if (!isObject(al)) return { ok: false, reason: "STATE_INVALID" };

    const budget = (state as any).budget;
    if (!isObject(budget) || !isObject(budget.budget_limit) || !isObject(budget.spent_in_period)) {
      return { ok: false, reason: "STATE_INVALID" };
    }

    const caps = (state as any).max_amount_per_action;
    if (!isObject(caps)) return { ok: false, reason: "STATE_INVALID" };

    const vel = (state as any).velocity;
    if (!isObject(vel) || !isObject(vel.config) || !isObject(vel.counters)) return { ok: false, reason: "STATE_INVALID" };
    if (typeof (vel.config as any).window_seconds !== "number" || typeof (vel.config as any).max_actions !== "number") {
      return { ok: false, reason: "STATE_INVALID" };
    }

    const rp = (state as any).replay;
    if (!isObject(rp) || typeof rp.window_seconds !== "number" || typeof rp.max_nonces_per_agent !== "number" || !isObject(rp.nonces)) {
      return { ok: false, reason: "STATE_INVALID" };
    }

    const cc = (state as any).concurrency;
    if (!isObject(cc) || !isObject(cc.max_concurrent) || !isObject(cc.active) || !isObject(cc.active_auths)) {
      return { ok: false, reason: "STATE_INVALID" };
    }

    const rc = (state as any).recursion;
    if (!isObject(rc) || !isObject(rc.max_depth)) return { ok: false, reason: "STATE_INVALID" };

    const tl = (state as any).tool_limits;
    if (!isObject(tl) || typeof tl.window_seconds !== "number" || !isObject(tl.max_calls) || !isObject(tl.calls)) {
      return { ok: false, reason: "STATE_INVALID" };
    }

    // Per-agent minimal config for this intent
    const agent = intent.agent_id;
    if (budget.budget_limit[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };
    if (caps[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };
    if (cc.max_concurrent[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };
    if (rc.max_depth[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };
    if (tl.max_calls[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };

    return { ok: true };

    
  }

  private validateIntent(intent: Intent): { ok: true } | { ok: false; reason: ReasonCode } {
    if (intent.type === "RELEASE" && !intent.authorization_id) {
      return { ok: false, reason: "STATE_INVALID" };
    }
    return { ok: true };
  }

  private emitAudit(event: AuditEvent): void {
    this.audit.append(event);
    this.auditEventCount += 1;
    if (!this.opts.auditSink) return;

    const sink = this.opts.auditSink;
    const queuedEvent = structuredClone(event);
    this.auditSinkChain = this.auditSinkChain
      .then(() => Promise.resolve(sink.append(queuedEvent)))
      .catch((error) => {
        this.auditSinkError ??= error;
      });
  }

  private maybeEmitCheckpoint(policyId: string, timestamp: number, state: State): void {
    const every = this.opts.checkpoint_every_n_events;
    if (every === undefined) return;
    if (!Number.isInteger(every) || every <= 0) return;
    if (this.auditEventCount % every !== 0) return;

    this.emitAudit({
      type: "STATE_CHECKPOINT",
      stateHash: this.computeStateHashFor(state),
      timestamp,
      policyId
    });
  }

  async flushAudit(): Promise<void> {
    await this.auditSinkChain;
    if (this.opts.auditSink?.flush) {
      await this.opts.auditSink.flush();
    }
    if (this.auditSinkError !== null) {
      const err = this.auditSinkError;
      this.auditSinkError = null;
      throw err;
    }
  }

  commitState(state: State): void {
    if (!this.opts.stateStore) return;
    const snapshot = this.exportState(state);
    const store = this.opts.stateStore;
    this.stateStoreChain = this.stateStoreChain
      .then(() => Promise.resolve(store.set(snapshot)))
      .catch((error) => {
        this.stateStoreError ??= error;
      });
  }

  async flushState(): Promise<void> {
    await this.stateStoreChain;
    if (this.stateStoreError !== null) {
      const err = this.stateStoreError;
      this.stateStoreError = null;
      throw err;
    }
  }

  evaluate(intent: Intent, state: State): EvaluateOutput {
    const out = this.evaluatePure(intent, state, { mode: "fail-fast" });

    if (out.decision === "DENY") {
      this.currentState = structuredClone(state);
      if (this.opts.autoPersist === true) {
        this.commitState(state);
      }
      return out;
    }

    Object.assign(state, out.nextState);
    this.currentState = structuredClone(state);
    if (this.opts.autoPersist === true) {
      this.commitState(state);
    }

    return { decision: "ALLOW", reasons: [], authorization: out.authorization };
  }

  verifyAuthorization(
    intent: Intent,
    authorization: Authorization,
    state: State,
    now?: number
  ): { valid: boolean; reason?: ReasonCode } {
    try {
      const t =
        now ??
        (() => {
          if (this.opts.strictDeterminism) {
            throw new Error("strictDeterminism: 'now' must be provided (no Date.now fallback)");
          }
          return Math.floor(Date.now() / 1000);
        })();

      const intent_hash = intentHash(intent);
      if (intent_hash !== authorization.intent_hash) return { valid: false, reason: "AUTH_INTENT_MISMATCH" };
      const expiry = authorization.expiry ?? authorization.expires_at;
      if (t > expiry) return { valid: false, reason: "AUTH_EXPIRED" };
      if (authorization.decision !== "ALLOW") return { valid: false, reason: "AUTH_SIGNATURE_INVALID" };
      if (state.policy_version !== authorization.policy_version) return { valid: false, reason: "POLICY_VERSION_MISMATCH" };

      const authPayload = {
        intent_hash: authorization.intent_hash,
        policy_version: authorization.policy_version,
        state_snapshot_hash: authorization.state_snapshot_hash,
        decision: "ALLOW" as const,
        expires_at: authorization.expires_at
      };

      const ok = engineVerifyHmac(authPayload, authorization.engine_signature, this.opts.engine_secret);
      if (!ok) return { valid: false, reason: "AUTH_SIGNATURE_INVALID" };

      return { valid: true };
    } catch {
      return { valid: false, reason: "INTERNAL_ERROR" };
    }
  }

  /**
   * evaluatePure — pure, deterministic evaluation of (intent, state, policy).
   *
   * The input `state` is never mutated. deepMerge creates new object copies at
   * every level touched by a module delta, so passing the same state reference
   * across sequential calls is safe.
   *
   * For concurrent evaluation in multi-threaded environments (e.g. worker
   * threads sharing a SharedArrayBuffer), callers should still provide
   * structuredClone(state) to each invocation for full isolation.
   */
  evaluatePure(intent: Intent, state: State, opts?: EngineEvalOptions): EvaluatePureOutput {

    const mode = opts?.mode ?? "fail-fast";

    const iv = this.validateIntent(intent);
    if (!iv.ok) return { decision: "DENY", reasons: [iv.reason] };

    // Fail-closed + explicit runtime validation
    const v = this.validateStateForIntent(state as unknown, intent);
    if (!v.ok) return { decision: "DENY", reasons: [v.reason] };

    if (state.policy_version !== this.opts.policy_version) {
      return { decision: "DENY", reasons: ["POLICY_VERSION_MISMATCH"] };
    }

    try {
      const intent_hash = intentHash(intent);
      const policyId = this.computePolicyId();
      this.emitAudit({
        type: "INTENT_RECEIVED",
        intent_hash,
        agent_id: intent.agent_id,
        timestamp: intent.timestamp,
        policyId
      });

      const t = intent.type ?? "EXECUTE";
      const modules = t === "RELEASE" ? RELEASE_MODULES : EXECUTE_MODULES;

      // ── Decision phase ──────────────────────────────────────────────────
      // (intent + state + module policies) → ALLOW | DENY + nextState
      const decisionResult = runDecisionModules({ intent, state, mode }, modules);

      if (decisionResult.decision === "DENY") {
        this.emitAudit({
          type: "DECISION",
          intent_hash,
          decision: "DENY",
          reasons: decisionResult.reasons,
          policy_version: state.policy_version,
          timestamp: intent.timestamp,
          policyId
        });
        this.maybeEmitCheckpoint(policyId, intent.timestamp, state);
        return { decision: "DENY", reasons: decisionResult.reasons };
      }

      // Authorization is bound to the post-decision state snapshot.
      // working carries all module deltas from the decision phase.
      let working = decisionResult.nextState;
      const state_snapshot_hash = this.computeStateHashFor(working);
      const issued_at = intent.timestamp;
      const expires_at = issued_at + this.authorizationTtlSeconds();
      const policy_id = policyId;
      const issuer = this.authorizationIssuer();
      const audience = this.authorizationAudience();
      const alg = this.authorizationSigningAlg();
      const kid = this.authorizationSigningKid();

      const authPayload = {
        intent_hash,
        policy_version: state.policy_version,
        state_snapshot_hash,
        decision: "ALLOW" as const,
        expires_at
      };

      const engine_signature = engineSignHmac(authPayload, this.opts.engine_secret);
      // state_hash binds the authorization to the evaluation-time input state.
      // Uses computeStateHashFor (module-codec canonical hash) rather than a raw
      // JSON hash so it is insensitive to key-insertion order and missing optional
      // fields — the same guarantee the engine already provides for state_snapshot_hash.
      // This allows the PEP boundary to verify the current state matches the state
      // the engine evaluated against via engine.computeStateHash(state).
      const state_hash = this.computeStateHashFor(state);

      const authorizationCorePayload: Record<string, unknown> = {
        auth_id: "",
        issuer,
        audience,
        intent_hash,
        state_hash,
        policy_id,
        decision: "ALLOW" as const,
        issued_at,
        expiry: expires_at,
        alg,
        kid,
        nonce: intent.nonce.toString()
      };
      if (intent.action_type !== undefined) authorizationCorePayload.capability = intent.action_type;

      // Derive a stable auth_id before signature attachment.
      const authorization_id = sha256HexFromJson({ ...authorizationCorePayload, engine_signature });
      const authCore = { ...authorizationCorePayload, auth_id: authorization_id };
      let signature: string;
      if (alg === "Ed25519") {
        if (!this.opts.authorization_private_key_pem) {
          throw new Error("authorization_private_key_pem is required for Ed25519 signing");
        }
        signature = signEd25519(SIGNING_DOMAINS.AUTH_V1, authCore, this.opts.authorization_private_key_pem);
      } else {
        signature = signHmacDomain(SIGNING_DOMAINS.AUTH_V1, authCore, this.opts.engine_secret);
      }

      const authorization: Authorization = {
        authorization_id,
        auth_id: authorization_id,
        issuer,
        audience,
        intent_hash,
        state_hash,
        policy_id,
        policy_version: state.policy_version,
        state_snapshot_hash,
        decision: "ALLOW",
        issued_at,
        expiry: expires_at,
        alg,
        kid,
        nonce: intent.nonce.toString(),
        signature,
        expires_at,
        engine_signature
      };
      if (intent.action_type !== undefined) authorization.capability = intent.action_type;

      if (t === "EXECUTE") {
        const agent = intent.agent_id;
        const current = working.concurrency.active_auths?.[agent] ?? {};

        working = deepMerge(working, {
          concurrency: {
            ...working.concurrency,
            active_auths: {
              ...working.concurrency.active_auths,
              [agent]: {
                ...current,
                [authorization.auth_id]: { expires_at: authorization.expiry }
              }
            }
          }
        });
      }

      this.emitAudit({
        type: "DECISION",
        intent_hash,
        decision: "ALLOW",
        reasons: [],
        policy_version: state.policy_version,
        timestamp: issued_at,
        policyId
      });

      this.emitAudit({
        type: "AUTH_EMITTED",
        authorization_id,
        intent_hash,
        expires_at,
        timestamp: issued_at,
        policyId
      });
      this.maybeEmitCheckpoint(policyId, issued_at, working);

      return { decision: "ALLOW", reasons: [], authorization, nextState: working };
    } catch {
      return { decision: "DENY", reasons: ["INTERNAL_ERROR"] };
    }

    
  }

  computePolicyId(): string {
    if (this.opts.policyId) return this.opts.policyId;
    const describeModules = (mods: readonly PolicyModule[]) =>
      [...mods]
        .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
        .map((m) => ({ id: m.id, version: (m as any).version ?? null }));
    const payload = stableStringify({
      engine: "PolicyEngine",
      engineVersion: ENGINE_VERSION,
      modules: {
        execute: describeModules(EXECUTE_MODULES),
        release: describeModules(RELEASE_MODULES)
      },
      opts: {
        policy_version: this.opts.policy_version ?? null,
        authorization_ttl_seconds: this.authorizationTtlSeconds(),
        deny_mode: this.opts.deny_mode ?? "fail-fast",
        strict: this.opts.strictDeterminism ?? false
      }
    });
    return createHash("sha256").update(payload, "utf8").digest("hex");
  }

  exportState(): CanonicalState;
  exportState(state: State): CanonicalState;
  exportState(state?: State): CanonicalState {
    const current = state ?? this.currentState;
    if (!current) throw new Error("exportState: engine has no current state");

    let snapshot = createCanonicalState({
      formatVersion: 1,
      engineVersion: ENGINE_VERSION,
      policyId: this.computePolicyId(),
      modules: {}
    });

    const ids = Object.keys(MODULE_CODECS).sort();
    for (const id of ids) {
      snapshot = withModuleState(snapshot, id, MODULE_CODECS[id].serializeState(current));
    }

    return snapshot;
  }

  importState(state: CanonicalState): void;
  importState(target: State, state: CanonicalState): void;
  importState(arg1: State | CanonicalState, arg2?: CanonicalState): void {
    const state = (arg2 ?? arg1) as CanonicalState;
    if (state.formatVersion !== 1) {
      throw new Error(`importState: unsupported formatVersion=${String((state as any).formatVersion)}`);
    }
    const expected = this.computePolicyId();
    if (state.policyId !== expected) {
      throw new Error(`importState: policyId mismatch (state=${state.policyId}, engine=${expected})`);
    }

    const target = arg2 ? (arg1 as State) : structuredClone(this.currentState);
    if (!target) throw new Error("importState: engine has no mutable state target");

    const ids = Object.keys(MODULE_CODECS).sort();
    for (const id of ids) {
      const codec = MODULE_CODECS[id];
      codec.deserializeState(target, state.modules[id]);
    }

    this.currentState = structuredClone(target);
  }

  computeStateHash(): string;
  computeStateHash(state: State): string;
  computeStateHash(state?: State): string {
    const current = state ?? this.currentState;
    if (!current) throw new Error("computeStateHash: engine has no current state");
    return this.computeStateHashFor(current);
  }

  simulateSequence(intents: Intent[], opts?: EngineEvalOptions): SimulationResult {
    const base = this.currentState;
    if (!base) throw new Error("simulateSequence: engine has no current state");

    let working = structuredClone(base);
    const outputs: EvaluatePureOutput[] = [];
    for (const intent of intents) {
      const out = this.evaluatePure(intent, working, opts);
      outputs.push(out);
      if (out.decision === "ALLOW") {
        working = out.nextState;
      }
    }

    return { outputs, finalState: working };
  }

  private computeStateHashFor(state: State): string {
    const ids = Object.keys(MODULE_CODECS).sort();
    const moduleHashes: Record<string, string> = {};
    for (const id of ids) {
      moduleHashes[id] = MODULE_CODECS[id].stateHash(state);
    }

    const bytes = new TextEncoder().encode(
      canonicalJson({
        formatVersion: 1,
        engineVersion: ENGINE_VERSION,
        policyId: this.computePolicyId(),
        modules: moduleHashes
      })
    );
    return createHash("sha256").update(bytes).digest("hex");
  }
  
}
