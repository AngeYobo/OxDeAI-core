// SPDX-License-Identifier: Apache-2.0
import type { Authorization, AuthorizationV1, DelegationScope, DelegationV1, Intent, KeySet, PolicyEngine, State } from "@oxdeai/core";
import type { ReplayStore } from "./replayStore.js";

/**
 * A runtime-agnostic description of an action an agent wants to perform.
 * Runtimes map their tool-call or action objects to this type before
 * passing them to the guard.
 */
export type ProposedAction = {
  /** Name of the action / tool being invoked (e.g. "provision_gpu"). */
  name: string;
  /** Arguments passed to the action. */
  args: Record<string, unknown>;
  /** Optional ambient context — agent_id and target are read from here by the default normalizer. */
  context?: Record<string, unknown>;
  /** Estimated monetary cost of the action in whole units (e.g. USD). Used to set the intent amount. */
  estimatedCost?: number;
  /** Resource category (e.g. "gpu", "payment"). Used to infer action_type. */
  resourceType?: string;
  /** Unix timestamp in seconds. Defaults to Date.now() / 1000 when omitted. */
  timestampSeconds?: number;
};

/**
 * Delegation credentials presented by a child agent to execute within a
 * delegated scope. The guard verifies the full chain before execution.
 */
export type GuardDelegationInput = {
  /** The DelegationV1 artifact issued by the parent agent. */
  delegation: DelegationV1;
  /** The parent AuthorizationV1 that the delegation was derived from. */
  parentAuth: AuthorizationV1;
  /**
   * The scope granted to the parent agent — the authority ceiling for this
   * delegation chain. Required for scope narrowing verification.
   * Absence or structural invalidity fails closed before chain verification.
   */
  parentScope: DelegationScope;
};

/**
 * Per-call options passed as the optional third argument to the guard function.
 * When `delegation` is present, the guard takes the delegation verification path
 * instead of the standard policy-evaluation path.
 */
export type GuardCallOptions = {
  /**
   * Delegation credentials for child-agent execution.
   * When provided, the guard skips engine.evaluatePure() and instead
   * verifies the delegation chain locally.
   */
  delegation?: GuardDelegationInput;
};

/** Structured record of the guard's decision, passed to the onDecision hook. */
export type GuardDecisionRecord = {
  action: ProposedAction;
  decision: "ALLOW" | "DENY";
  authorization?: Authorization;
  /** Present when the decision was made via the delegation verification path. */
  delegation?: DelegationV1;
  reasons?: string[];
};

/**
 * Opaque version token associated with a state snapshot.
 * Returned by getState() and passed back to setState() to enforce CAS semantics.
 * Use a monotonically-increasing integer, ETag, or any comparable value.
 */
export type StateVersion = string | number;

/**
 * A state snapshot paired with its version token.
 * Returned by getState() so the guard can detect concurrent modifications.
 */
export type VersionedState = {
  state: State;
  version: StateVersion;
};

/** Configuration for OxDeAIGuard. */
export type OxDeAIGuardConfig = {
  /** The PolicyEngine instance that evaluates intent policy. */
  engine: PolicyEngine;
  /**
   * Load the current policy state together with its version token.
   * The version is passed back to setState() to enforce CAS semantics.
   * May be async.
   */
  getState: () => VersionedState | Promise<VersionedState>;
  /**
   * Persist the next state using compare-and-set semantics.
   * Must atomically verify that the persisted version still equals
   * `expectedVersion` before committing `state`. Return `true` on
   * success, `false` on version mismatch (concurrent modification).
   * The guard throws OxDeAIConflictError and blocks execution on `false`.
   * May be async.
   */
  setState: (state: State, expectedVersion: StateVersion) => boolean | Promise<boolean>;

  /**
   * Optional custom mapping from a ProposedAction to an OxDeAI Intent.
   * When omitted, the default normalizer is used.
   */
  mapActionToIntent?: (action: ProposedAction) => Intent;

  /**
   * Optional hook called after authorization succeeds but before the
   * side-effecting execute() callback is invoked.
   */
  beforeExecute?: (
    action: ProposedAction,
    authorization: Authorization
  ) => void | Promise<void>;

  /**
   * Optional audit hook called after every decision (ALLOW and DENY).
   * Errors thrown here are swallowed so they cannot block execution.
   */
  onDecision?: (result: GuardDecisionRecord) => void | Promise<void>;

  /**
   * The audience this guard instance expects in every AuthorizationV1 artifact.
   *
   * Must equal the `authorization_audience` value configured in the PolicyEngine
   * (typically the agent's identity string). Every authorization issued by the
   * engine carries this audience; the guard rejects tokens whose audience field
   * does not exactly match.
   *
   * For adapter packages (openclaw, langgraph, crewai, etc.) this is derived
   * automatically from `config.agentId` — callers do not set it directly.
   *
   * Enforcement: `validateConfig` throws `OxDeAIGuardConfigurationError` when
   * absent. There is no default or fallback.
   */
  expectedAudience: string;

  /**
   * KeySets used to verify Ed25519 signatures on authorization artifacts.
   * Required; `validateConfig` throws when absent or empty.
   */
  trustedKeySets?: KeySet | readonly KeySet[];

  /**
   * Pluggable replay store for durable auth_id and delegation_id tracking.
   *
   * When omitted, an in-memory store is created per guard instance (equivalent
   * to the previous single-process behavior). Provide a backend-backed
   * implementation (e.g. Redis, DynamoDB) for multi-process or
   * restart-durable replay prevention.
   *
   * The store MUST be fail-closed: throw rather than return a permissive
   * result when unavailable. The guard treats any thrown error as DENY.
   */
  replayStore?: ReplayStore;

  /**
   * Optional custom function for computing the live-state hash used in
   * state_hash binding verification (guard step 6c).
   *
   * When provided, this function is called instead of
   * `config.engine.computeStateHash(state)` to produce the hash that is
   * compared against `authorization.state_hash`.
   *
   * Required when authorizations are produced by an external provider that
   * uses a different state canonicalization algorithm. For example:
   *   - Sift adapter: uses siftCanonicalJsonHash(state)
   *   - Core PolicyEngine: uses engine.computeStateHash(state) (default)
   *
   * Using the wrong function for the authorization's committed hash algorithm
   * produces a deterministic state_hash mismatch — execution is blocked,
   * fail-closed. There is no fallback or partial acceptance.
   *
   * Fail-closed: any exception thrown by this function blocks execution
   * with OxDeAIAuthorizationError.
   */
  computeStateHash?: (state: State) => string;
};
