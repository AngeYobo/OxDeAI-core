// SPDX-License-Identifier: Apache-2.0
import type { Authorization, AuthorizationV1, DelegationScope, Intent, KeySet } from "@oxdeai/core";
import { verifyDelegationChain, verifyAuthorization as strictVerifyAuthorization, intentHash } from "@oxdeai/core";
import type { OxDeAIGuardConfig, ProposedAction, GuardDecisionRecord, GuardCallOptions } from "./types.js";
import { defaultNormalizeAction } from "./normalizeAction.js";
import { createInMemoryReplayStore } from "./replayStore.js";
import type { ReplayStore } from "./replayStore.js";
import { createLifecycle, emitBoundaryEvent, reject } from "./boundaryEvent.js";
import type { GuardLifecycle } from "./boundaryEvent.js";
import type { ProvenanceRecord } from "./provenance.js";
import {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAIConflictError,
  OxDeAIDelegationError,
  OxDeAIGuardConfigurationError,
  OxDeAINormalizationError,
  OxDeAIProvenanceConflictError,
} from "./errors.js";

// ── validation ────────────────────────────────────────────────────────────────

/**
 * The engine's public DENY contract is `{ decision: "DENY"; reasons: ReasonCode[] }`
 * (`ReasonCode` is a string union at runtime). `config.engine` is validated only
 * structurally (`validateConfig` above requires an `evaluatePure` function), so
 * it need not be a real `PolicyEngine` instance — a test double, a custom
 * implementation, or a future engine version can return a `DENY` whose
 * `reasons` do not match this contract. Reading such a value without checking
 * it first (`evalResult.reasons.map(String)`) throws an unclassified,
 * unstructured `TypeError` instead of failing closed as an engine-contract
 * violation. See #247.
 */
function isValidDenyReasons(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((r) => typeof r === "string");
}

function isValidDelegationScope(scope: unknown): scope is DelegationScope {
  if (scope === null || scope === undefined || typeof scope !== "object" || Array.isArray(scope)) {
    return false;
  }
  const s = scope as Record<string, unknown>;
  if (s.tools !== undefined && !Array.isArray(s.tools)) return false;
  if (s.max_amount !== undefined && typeof s.max_amount !== "bigint") return false;
  if (s.max_actions !== undefined && typeof s.max_actions !== "number") return false;
  if (s.max_depth !== undefined && typeof s.max_depth !== "number") return false;
  return true;
}

function validateConfig(config: OxDeAIGuardConfig): void {
  if (!config || typeof config !== "object") {
    throw new OxDeAIGuardConfigurationError("config must be a plain object.");
  }
  if (!config.engine || typeof config.engine.evaluatePure !== "function") {
    throw new OxDeAIGuardConfigurationError("config.engine must be a PolicyEngine instance with an evaluatePure method.");
  }
  if (typeof config.getState !== "function") {
    throw new OxDeAIGuardConfigurationError("config.getState must be a function.");
  }
  if (typeof config.setState !== "function") {
    throw new OxDeAIGuardConfigurationError("config.setState must be a function.");
  }
  if (typeof config.expectedAudience !== "string" || config.expectedAudience.length === 0) {
    throw new OxDeAIGuardConfigurationError(
      "config.expectedAudience is required and must be a non-empty string. " +
      "Set it to the agent identity this guard instance protects (matches authorization_audience in PolicyEngine)."
    );
  }
}

// ── decision audit ────────────────────────────────────────────────────────────

async function fireDecision(
  onDecision: OxDeAIGuardConfig["onDecision"],
  record: GuardDecisionRecord
): Promise<void> {
  if (!onDecision) return;
  try {
    await onDecision(record);
  } catch {
    // Audit hook errors must never block execution or propagate to callers.
  }
}

// ── guard factory ─────────────────────────────────────────────────────────────

/**
 * OxDeAIGuard — Universal Policy Enforcement Point (PEP).
 *
 * Returns a reusable async guard function. Call it with a ProposedAction and
 * an execute callback. The guard will:
 *   1. Load current state + version.
 *   2. Normalize the action to an Intent.
 *   3. Evaluate policy via engine.evaluatePure().
 *   4. On DENY → throw OxDeAIDenyError (execute is never called).
 *   5. On ALLOW → verify the authorization artifact.
 *   6. Verify state_hash binding.
 *   7. CAS setState(nextState, version) — throws OxDeAIConflictError on mismatch.
 *   8. Call optional beforeExecute hook.
 *   9. Invoke execute().
 *  10. Fire onDecision audit hook.
 *  11. Return the execute() result.
 *
 * Delegation path (when opts.delegation is provided):
 *   1. Normalize the action to an Intent (scope amount check).
 *   2. Verify the DelegationV1 chain locally (no engine call).
 *   3. Check proposed action is within delegation scope (tools, max_amount).
 *   4. Call optional beforeExecute hook.
 *   5. Invoke execute().
 *   6. Fire onDecision audit hook. setState is NOT called.
 *   7. Return the execute() result.
 *
 * Security invariants:
 *   - DENY with malformed reasons → OxDeAIAuthorizationError (no execution, no
 *     decision record, no synthetic DENY — see #247).
 *   - ALLOW without authorization → OxDeAIAuthorizationError (no execution).
 *   - ALLOW without nextState     → OxDeAIAuthorizationError (no execution).
 *   - verifyAuthorization failure → OxDeAIAuthorizationError (no execution).
 *   - state_hash mismatch         → OxDeAIAuthorizationError (no execution, no setState).
 *   - CAS setState returns false  → OxDeAIConflictError (no execution side effects).
 *   - Missing version from store  → OxDeAIAuthorizationError (no execution).
 *   - Delegation chain failure    → OxDeAIDelegationError (no execution).
 *   - Scope violation             → OxDeAIDelegationError (no execution).
 *   - Normalization failure       → OxDeAINormalizationError (no execution).
 *   - Evaluation / state errors   → re-thrown (fail-closed).
 *
 * Audit streams (disjoint — no rejection appears on both):
 *
 * ```text
 * policy DENY                -> onDecision only        (decision record emitted)
 * guard rejection before execute() starts
 *                            -> onBoundaryEvent only   (no decision record emitted)
 * ALLOW, callback then threw -> neither                (current contract, #238)
 * ```
 *
 * Both hooks are best effort: whatever they throw is swallowed, and the caller
 * always receives the original guard error, unwrapped and unreplaced.
 */
export function OxDeAIGuard(config: OxDeAIGuardConfig) {
  validateConfig(config);

  const normalize: (action: ProposedAction) => Intent =
    config.mapActionToIntent ?? defaultNormalizeAction;
  const trustedKeySets: readonly KeySet[] | undefined = config.trustedKeySets
    ? Array.isArray(config.trustedKeySets)
      ? config.trustedKeySets
      : [config.trustedKeySets]
    : undefined;

  if (!trustedKeySets || trustedKeySets.length === 0) {
    throw new OxDeAIGuardConfigurationError(
      "trustedKeySets are required for authorization verification and must not be empty."
    );
  }

  // Pluggable replay store. Defaults to in-memory (single-process semantics).
  // Replace with a durable backend for multi-process / restart-durable deployments.
  const replayStore: ReplayStore = config.replayStore ?? createInMemoryReplayStore();

  /**
   * The enforcement body. Extracted so that every rejection leaves through one
   * catch in `guard` below, rather than each throw site having to remember to
   * report itself.
   */
  async function runRequest(
    action: ProposedAction,
    execute: () => Promise<unknown>,
    opts: GuardCallOptions | undefined,
    lifecycle: GuardLifecycle
  ): Promise<unknown> {
    // ── 1. Load state + version ────────────────────────────────────────────
    const versioned = await config.getState();
    const state = versioned.state;
    const version = versioned.version;

    // Fail closed if the store did not return a version.
    if (version === undefined || version === null) {
      throw reject(
        "STATE_LOAD",
        "STATE_VERSION_MISSING",
        new OxDeAIAuthorizationError(
          "State store returned no version. Cannot enforce CAS invariant. Execution blocked."
        )
      );
    }

    // ── 2. Normalize action → intent ───────────────────────────────────────
    lifecycle.stage = "NORMALIZATION";
    let intent: Intent;
    try {
      intent = normalize(action);
    } catch (err) {
      if (err instanceof OxDeAINormalizationError) {
        throw reject("NORMALIZATION", "NORMALIZATION_FAILURE", err);
      }
      // The secure path performs trusted-vs-proposer reconciliation inside the
      // normalizer, so a provenance conflict surfaces here. It is an
      // authorization boundary failure, not a normalization failure, and must
      // reach the caller with its own type and conflicting-field list intact.
      if (err instanceof OxDeAIProvenanceConflictError) {
        throw reject("PROVENANCE", "PROVENANCE_CONFLICT", err, {
          conflictingFields: err.fields,
          // The error predates the boundary event and types its record as a
          // plain string map; every value in it is a ClaimProvenance by
          // construction (provenance.ts builds it from that union).
          provenance: err.provenance as ProvenanceRecord,
        });
      }
      // Custom mapActionToIntent threw something unexpected — fail closed.
      throw reject(
        "NORMALIZATION",
        "NORMALIZATION_FAILURE",
        new OxDeAINormalizationError(
          `mapActionToIntent threw an unexpected error: ${err instanceof Error ? err.message : String(err)}`
        )
      );
    }
    lifecycle.intentId = intent.intent_id;

    // ── 3. Delegation path ─────────────────────────────────────────────────
    if (opts?.delegation) {
      lifecycle.stage = "DELEGATION";
      const { delegation, parentAuth } = opts.delegation;

      if (!delegation || !parentAuth) {
        throw reject(
          "DELEGATION",
          "DELEGATION_INPUT_INVALID",
          new OxDeAIAuthorizationError(
            "Delegation input is incomplete: both delegation and parentAuth are required. Execution blocked."
          )
        );
      }

      const now = Math.floor(Date.now() / 1000);
      const violationMessages: string[] = [];

      // Atomically check-and-consume the delegation_id. Fail closed on store errors.
      let delegConsumed: boolean;
      try {
        delegConsumed = replayStore.consumeDelegationId
          ? await replayStore.consumeDelegationId(delegation.delegation_id, { expiry: delegation.expiry })
          : true;
      } catch (err) {
        throw reject(
          "REPLAY",
          "REPLAY_STORE_UNAVAILABLE",
          new OxDeAIAuthorizationError(
            `Replay store unavailable for delegation_id: ${err instanceof Error ? err.message : String(err)}. Execution blocked.`
          )
        );
      }
      if (!delegConsumed) {
        throw reject(
          "REPLAY",
          "DELEGATION_REPLAY",
          new OxDeAIAuthorizationError("Delegation replay detected. Execution blocked.")
        );
      }
      // Only a store that implements the optional check-and-consume actually
      // consumed anything; the fallback above assumes success without a store.
      lifecycle.delegationConsumed = replayStore.consumeDelegationId !== undefined;

      // Verify delegation chain:
      //   - parent hash binding
      //   - parent expiry
      //   - delegator === parent.audience
      //   - policy_id binding
      //   - delegation expiry <= parent expiry
      //   - delegation expiry
      //   - delegation signature (if trustedKeySets provided)
      //   - scope narrowing against parent (enforced via parentScope)
      //
      // Validate parentScope before chain verification. Fail closed on missing or malformed scope.
      const { parentScope } = opts.delegation;
      if (!isValidDelegationScope(parentScope)) {
        throw reject(
          "DELEGATION",
          "DELEGATION_INPUT_INVALID",
          new OxDeAIAuthorizationError(
            "Parent authorization scope is missing or malformed. Execution blocked."
          )
        );
      }

      const chainResult = verifyDelegationChain(delegation, parentAuth, {
        now,
        trustedKeySets: config.trustedKeySets,
        requireSignatureVerification: true,
        parentScope,
      });

      if (!chainResult.ok) {
        for (const v of chainResult.violations) {
          violationMessages.push(v.message ?? v.code);
        }
      }

      // Guard-level scope enforcement: is the proposed action within
      // the delegation's declared scope?
      if (delegation.scope.tools !== undefined && !delegation.scope.tools.includes(action.name)) {
        violationMessages.push(
          `action "${action.name}" is not permitted by delegation scope.tools [${delegation.scope.tools.join(", ")}]`
        );
      }

      if (delegation.scope.max_amount !== undefined && intent.amount > delegation.scope.max_amount) {
        violationMessages.push(
          `intent amount ${intent.amount} exceeds delegation scope.max_amount ${delegation.scope.max_amount}`
        );
      }

      // Require scope presence for narrowing; fail closed if absent.
      if (!delegation.scope) {
        violationMessages.push("delegation.scope is required for narrowing; execution blocked.");
      }

      if (violationMessages.length > 0) {
        throw reject(
          "DELEGATION",
          "DELEGATION_VERIFICATION_FAILED",
          new OxDeAIDelegationError(violationMessages)
        );
      }

      // Enforce strict verification on the parent Authorization as well.
      // Atomically check-and-consume the parentAuth auth_id. Fail closed on store errors.
      let parentAuthConsumed: boolean;
      try {
        parentAuthConsumed = await replayStore.consumeAuthId(
          parentAuth.auth_id, { expiry: parentAuth.expiry }
        );
      } catch (err) {
        throw reject(
          "REPLAY",
          "REPLAY_STORE_UNAVAILABLE",
          new OxDeAIAuthorizationError(
            `Replay store unavailable for parentAuth auth_id: ${err instanceof Error ? err.message : String(err)}. Execution blocked.`
          )
        );
      }
      if (!parentAuthConsumed) {
        throw reject(
          "REPLAY",
          "AUTHORIZATION_REPLAY",
          new OxDeAIAuthorizationError(
            "Authorization replay detected on parentAuth: auth_id already consumed. Execution blocked."
          )
        );
      }
      lifecycle.authorizationConsumed = true;

      const parentAuthResult = strictVerifyAuthorization(parentAuth as AuthorizationV1, {
        now,
        mode: "strict",
        trustedKeySets,
        requireSignatureVerification: true,
        expectedPolicyId: parentAuth.policy_id,
        expectedAudience: config.expectedAudience,
        expectedIssuer: parentAuth.issuer,
      });

      if (parentAuthResult.status !== "ok") {
        const reasons =
          parentAuthResult.violations?.map((v) => v.code).join(", ") ||
          parentAuthResult.status ||
          "unknown reason";
        throw reject(
          "AUTHORIZATION_VERIFICATION",
          "AUTHORIZATION_VERIFICATION_FAILED",
          new OxDeAIAuthorizationError(`Parent authorization verification failed: ${reasons}. Execution blocked.`)
        );
      }

      // parentAuth is AuthorizationV1; cast to Authorization for hook/audit
      // compatibility. Legacy fields will be absent — callers on the delegation
      // path should treat the value as AuthorizationV1 shape only.
      const parentAuthCompat = parentAuth as unknown as Authorization;

      // ── Delegation: beforeExecute hook ────────────────────────────────
      lifecycle.stage = "EXECUTION_GATE";
      if (config.beforeExecute) {
        await config.beforeExecute(action, parentAuthCompat);
      }

      // ── Delegation: execute ───────────────────────────────────────────
      // Marked BEFORE control enters the callback, not after it returns: a
      // failure raised inside the callback is not a guard-boundary rejection,
      // and the guard has already permitted the action by this line. Moving
      // this assignment below the await would silently re-classify every
      // callback failure as a guard refusal.
      lifecycle.executionStarted = true;
      const result = await execute();

      // ── Delegation: audit hook (no setState — parent state is authoritative) ──
      await fireDecision(config.onDecision, {
        action,
        decision: "ALLOW",
        authorization: parentAuthCompat,
        delegation,
      });

      return result;
    }

    // ── 4. Standard path: evaluate policy ─────────────────────────────────
    // evaluationTime follows the same capture pattern already used elsewhere
    // in this function for `now` (delegation-chain and post-hoc authorization
    // verification, above/below) — this is not a new trusted-clock mechanism,
    // just the existing one applied to the now-mandatory evaluatePure
    // parameter. It is not independently trusted or monotonic; reliable
    // PEP-side clock capture remains deferred.
    lifecycle.stage = "POLICY_EVALUATION";
    const evaluationTime = Math.floor(Date.now() / 1000);
    let evalResult: ReturnType<typeof config.engine.evaluatePure>;
    try {
      evalResult = config.engine.evaluatePure(intent, state, evaluationTime);
    } catch (err) {
      // Engine errors are never swallowed — callers must handle them.
      throw reject(
        "POLICY_EVALUATION",
        "ENGINE_FAILURE",
        new OxDeAIAuthorizationError(
          `PolicyEngine.evaluatePure threw: ${err instanceof Error ? err.message : String(err)}`
        )
      );
    }
    lifecycle.policyEvaluated = true;

    // ── 5. DENY path ───────────────────────────────────────────────────────
    if (evalResult.decision === "DENY") {
      // Validate the engine's DENY contract before reading `reasons`. A
      // malformed result (missing, null, non-array, or containing non-string
      // elements) is an engine-contract violation, not a policy decision: it
      // must fail closed without a decision record and without ever
      // constructing OxDeAIDenyError from unvalidated data. See #247.
      const rawReasons: unknown = evalResult.reasons;
      if (!isValidDenyReasons(rawReasons)) {
        throw reject(
          "POLICY_EVALUATION",
          "ENGINE_FAILURE",
          new OxDeAIAuthorizationError(
            "PolicyEngine returned DENY with malformed reasons: expected an array of strings. " +
              "Execution blocked."
          )
        );
      }
      await fireDecision(config.onDecision, {
        action,
        decision: "DENY",
        reasons: rawReasons,
      });
      throw new OxDeAIDenyError(rawReasons);
    }

    // ── 6. ALLOW: require authorization artifact and nextState ─────────────
    if (!evalResult.authorization) {
      throw reject(
        "POLICY_EVALUATION",
        "AUTHORIZATION_MISSING",
        new OxDeAIAuthorizationError(
          "PolicyEngine returned ALLOW without an authorization artifact. Execution blocked."
        )
      );
    }
    if (!evalResult.nextState) {
      // An ALLOW with no next state is an engine contract violation, not a
      // missing artifact: the artifact is present and the result is unusable.
      throw reject(
        "POLICY_EVALUATION",
        "ENGINE_FAILURE",
        new OxDeAIAuthorizationError(
          "PolicyEngine returned ALLOW without a nextState. Execution blocked."
        )
      );
    }
    lifecycle.authorizationIssued = true;

    const { authorization, nextState } = evalResult;

    // ── 6b. Verify the authorization artifact (strict verifier, fail-closed) ─
    lifecycle.stage = "AUTHORIZATION_VERIFICATION";
    const now = Math.floor(Date.now() / 1000);

    // Atomically check-and-consume the auth_id before execution. Fail closed on store errors.
    let authConsumed: boolean;
    try {
      authConsumed = await replayStore.consumeAuthId(
        authorization.auth_id, { expiry: (authorization as AuthorizationV1).expiry ?? 0 }
      );
    } catch (err) {
      throw reject(
        "REPLAY",
        "REPLAY_STORE_UNAVAILABLE",
        new OxDeAIAuthorizationError(
          `Replay store unavailable: ${err instanceof Error ? err.message : String(err)}. Execution blocked.`
        )
      );
    }
    if (!authConsumed) {
      throw reject(
        "REPLAY",
        "AUTHORIZATION_REPLAY",
        new OxDeAIAuthorizationError("Authorization replay detected: auth_id already consumed. Execution blocked.")
      );
    }
    lifecycle.authorizationConsumed = true;

    const authResult = strictVerifyAuthorization(authorization as AuthorizationV1, {
      now,
      mode: "strict",
      trustedKeySets,
      requireSignatureVerification: true,
      expectedPolicyId: authorization.policy_id,
      expectedAudience: config.expectedAudience,
      expectedIssuer: authorization.issuer,
    });

    if (authResult.status !== "ok") {
      const reasons =
        authResult.violations?.map((v) => v.code).join(", ") || authResult.status || "unknown reason";
      throw reject(
        "AUTHORIZATION_VERIFICATION",
        "AUTHORIZATION_VERIFICATION_FAILED",
        new OxDeAIAuthorizationError(`Authorization verification failed: ${reasons}. Execution blocked.`)
      );
    }

    // ── 6d. Enforce intent_hash binding ──────────────────────────────────────
    // Recompute the intent hash from the normalized intent and compare with the
    // authorization artifact's committed intent_hash. This binds execution to
    // exactly the verified canonical intent derived from the incoming action.
    // Fail closed on any canonicalization error — no ambiguity is permissible.
    let computedIntentHash: string;
    try {
      computedIntentHash = intentHash(intent);
    } catch (err) {
      // A canonicalization failure and a computed mismatch are the same audit
      // fact: the intent binding could not be established, so nothing may run.
      throw reject(
        "AUTHORIZATION_VERIFICATION",
        "INTENT_HASH_MISMATCH",
        new OxDeAIAuthorizationError(
          `Intent canonicalization failed: ${err instanceof Error ? err.message : String(err)}. Execution blocked.`
        )
      );
    }
    if (computedIntentHash !== (authorization as AuthorizationV1).intent_hash) {
      throw reject(
        "AUTHORIZATION_VERIFICATION",
        "INTENT_HASH_MISMATCH",
        new OxDeAIAuthorizationError(
          "Intent hash mismatch: computed hash does not match authorization.intent_hash. Execution blocked."
        )
      );
    }

    // ── 6c. Enforce state hash binding ────────────────────────────────────
    // The authorization artifact commits to the execution-time state snapshot
    // that the policy engine evaluated. Verify the current state matches.
    // Fail closed on mismatch, missing hash, or canonicalization failure.
    //
    // Hash strategy: config.computeStateHash takes precedence over
    // config.engine.computeStateHash. Use config.computeStateHash when the
    // authorization was produced by a provider with a different state
    // canonicalization algorithm (e.g., Sift adapter: siftCanonicalJsonHash).
    // Using the wrong strategy produces a deterministic mismatch — fail-closed.
    const expectedStateHash = (authorization as AuthorizationV1).state_hash;
    if (!expectedStateHash) {
      // As with the intent binding: absent, uncomputable and unequal are one
      // audit fact — the state binding does not hold.
      throw reject(
        "AUTHORIZATION_VERIFICATION",
        "STATE_HASH_MISMATCH",
        new OxDeAIAuthorizationError(
          "Authorization is missing state_hash. Execution blocked."
        )
      );
    }
    const computeHash = config.computeStateHash ?? ((s) => config.engine.computeStateHash(s));
    let actualStateHash: string;
    try {
      actualStateHash = computeHash(state);
    } catch (err) {
      throw reject(
        "AUTHORIZATION_VERIFICATION",
        "STATE_HASH_MISMATCH",
        new OxDeAIAuthorizationError(
          `State canonicalization failed: ${err instanceof Error ? err.message : String(err)}. Execution blocked.`
        )
      );
    }
    if (actualStateHash !== expectedStateHash) {
      throw reject(
        "AUTHORIZATION_VERIFICATION",
        "STATE_HASH_MISMATCH",
        new OxDeAIAuthorizationError(
          "Authorization state_hash does not match the current execution-time state snapshot. Execution blocked."
        )
      );
    }

    // ── 7. CAS state commit (before execution side effects) ──────────────
    // Commit the new state atomically. This must happen before execute() so
    // that a version mismatch (concurrent modification) blocks execution
    // without committing any side effects.
    lifecycle.stage = "STATE_COMMIT";
    const casOk = await config.setState(nextState, version);
    if (!casOk) {
      throw reject(
        "STATE_COMMIT",
        "CAS_CONFLICT",
        new OxDeAIConflictError(
          "State version mismatch: concurrent modification detected. Execution blocked."
        )
      );
    }
    lifecycle.stateCommitted = true;

    // ── 8. beforeExecute hook ──────────────────────────────────────────────
    lifecycle.stage = "EXECUTION_GATE";
    if (config.beforeExecute) {
      await config.beforeExecute(action, authorization);
    }

    // ── 9. Execute the side effect ─────────────────────────────────────────
    // Marked BEFORE control enters the callback, not after it returns: a
    // failure raised inside the callback is not a guard-boundary rejection,
    // and the guard has already permitted the action by this line. Moving this
    // assignment below the await would silently re-classify every callback
    // failure as a guard refusal.
    lifecycle.executionStarted = true;
    const result = await execute();

    // ── 10. Fire audit hook ────────────────────────────────────────────────
    await fireDecision(config.onDecision, {
      action,
      decision: "ALLOW",
      authorization,
    });

    // ── 11. Return result ──────────────────────────────────────────────────
    return result;
  }

  return async function guard(
    action: ProposedAction,
    execute: () => Promise<unknown>,
    opts?: GuardCallOptions
  ): Promise<unknown> {
    const lifecycle = createLifecycle("STATE_LOAD");
    try {
      return await runRequest(action, execute, opts, lifecycle);
    } catch (err) {
      // Unconditional: every emission rule lives in emitBoundaryEvent, so this
      // catch cannot drift into deciding what counts as a rejection. The
      // ORIGINAL error is re-thrown regardless of what the audit sink does.
      await emitBoundaryEvent(config.onBoundaryEvent, err, lifecycle);
      throw err;
    }
  };
}
