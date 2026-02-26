import type { Intent } from "../types/intent.js";
import type { State } from "../types/state.js";
import type { Authorization } from "../types/authorization.js";
import type { ReasonCode, PolicyResult } from "../types/policy.js";

import { sha256HexFromJson } from "../crypto/hashes.js";
import { engineSignHmac } from "../crypto/sign.js";
import { engineVerifyHmac } from "../crypto/verify.js";

import { HashChainedLog } from "../audit/HashChainedLog.js";
import { KillSwitchModule } from "./modules/KillSwitchModule.js";
import { AllowlistModule } from "./modules/AllowlistModule.js";
import { BudgetModule } from "./modules/BudgetModule.js";
import { VelocityModule } from "./modules/VelocityModule.js";

export type EvaluateOutput =
  | { decision: "ALLOW"; reasons: []; authorization: Authorization }
  | { decision: "DENY"; reasons: ReasonCode[] };

export type EngineOptions = {
  policy_version: string;
  engine_secret: string;
  authorization_ttl_seconds: number;
};

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

export class PolicyEngine {
  private readonly opts: EngineOptions;
  private readonly usedNonces = new Set<string>(); // v0.1 replay protection (in-memory)
  public readonly audit: HashChainedLog = new HashChainedLog();

  constructor(opts: EngineOptions) {
    this.opts = opts;
  }

  private nonceKey(intent: Intent): string {
    return `${intent.agent_id}:${intent.nonce.toString()}`;
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
    const requiredTop = ["period_id", "kill_switch", "allowlists", "budget", "max_amount_per_action", "velocity"];
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

    // Per-agent minimal config for this intent
    const agent = intent.agent_id;
    if (budget.budget_limit[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };
    if (caps[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };

    return { ok: true };
  }

  evaluate(intent: Intent, state: State): EvaluateOutput {
    // Fail-closed + explicit runtime validation
    const v = this.validateStateForIntent(state as unknown, intent);
    if (!v.ok) return { decision: "DENY", reasons: [v.reason] };

    // Specific reason for version mismatch
    if (state.policy_version !== this.opts.policy_version) {
      return { decision: "DENY", reasons: ["POLICY_VERSION_MISMATCH"] };
    }

    // From here: try/catch only guards truly unexpected runtime faults
    try {
      const intent_hash = sha256HexFromJson(intent);
      this.audit.append({
        type: "INTENT_RECEIVED",
        intent_hash,
        agent_id: intent.agent_id,
        timestamp: intent.timestamp
      });

      // Replay protection
      const nk = this.nonceKey(intent);
      if (this.usedNonces.has(nk)) {
        const out: EvaluateOutput = { decision: "DENY", reasons: ["REPLAY_NONCE"] };
        this.audit.append({
          type: "DECISION",
          intent_hash,
          decision: "DENY",
          reasons: out.reasons,
          policy_version: state.policy_version,
          timestamp: intent.timestamp
        });
        return out;
      }

      const results: PolicyResult[] = [
        KillSwitchModule(intent, state),
        AllowlistModule(intent, state),
        BudgetModule(intent, state),
        VelocityModule(intent, state)
      ];

      const denyReasons: ReasonCode[] = [];
      for (const r of results) if (r.decision === "DENY") denyReasons.push(...r.reasons);

      if (denyReasons.length) {
        const out: EvaluateOutput = { decision: "DENY", reasons: denyReasons };
        this.audit.append({
          type: "DECISION",
          intent_hash,
          decision: "DENY",
          reasons: denyReasons,
          policy_version: state.policy_version,
          timestamp: intent.timestamp
        });
        return out;
      }

      // Commit (v0.1 single-threaded assumption)
      this.usedNonces.add(nk);

      // Update budget spend
      const spent = state.budget.spent_in_period[intent.agent_id] ?? 0n;
      state.budget.spent_in_period[intent.agent_id] = spent + intent.amount;

      // Update velocity counter
      const cfg = state.velocity.config;
      const c = state.velocity.counters[intent.agent_id];
      const now = intent.timestamp;
      if (!c || now >= c.window_start + cfg.window_seconds) {
        state.velocity.counters[intent.agent_id] = { window_start: now, count: 1 };
      } else {
        state.velocity.counters[intent.agent_id] = { window_start: c.window_start, count: c.count + 1 };
      }

      const state_snapshot_hash = sha256HexFromJson(state);
      const expires_at = now + this.opts.authorization_ttl_seconds;

      const authPayload = {
        intent_hash,
        policy_version: state.policy_version,
        state_snapshot_hash,
        decision: "ALLOW" as const,
        expires_at
      };

      const engine_signature = engineSignHmac(authPayload, this.opts.engine_secret);
      const authorization_id = sha256HexFromJson({ ...authPayload, engine_signature });

      const authorization: Authorization = {
        authorization_id,
        intent_hash,
        policy_version: state.policy_version,
        state_snapshot_hash,
        decision: "ALLOW",
        expires_at,
        engine_signature
      };

      this.audit.append({
        type: "DECISION",
        intent_hash,
        decision: "ALLOW",
        reasons: [],
        policy_version: state.policy_version,
        timestamp: now
      });

      this.audit.append({
        type: "AUTH_EMITTED",
        authorization_id,
        intent_hash,
        expires_at,
        timestamp: now
      });

      return { decision: "ALLOW", reasons: [], authorization };
    } catch {
      // If validateState() passed, INTERNAL_ERROR should be rare and indicates a true bug.
      return { decision: "DENY", reasons: ["INTERNAL_ERROR"] };
    }
  }

  verifyAuthorization(
    intent: Intent,
    authorization: Authorization,
    state: State,
    now?: number
  ): { valid: boolean; reason?: ReasonCode } {
    try {
      const t = now ?? Math.floor(Date.now() / 1000);

      const intent_hash = sha256HexFromJson(intent);
      if (intent_hash !== authorization.intent_hash) return { valid: false, reason: "AUTH_INTENT_MISMATCH" };
      if (t > authorization.expires_at) return { valid: false, reason: "AUTH_EXPIRED" };
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
}
