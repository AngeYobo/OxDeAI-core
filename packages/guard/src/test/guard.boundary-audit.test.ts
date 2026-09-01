// SPDX-License-Identifier: Apache-2.0
/**
 * Unified guard-boundary audit emission (#235).
 *
 * `onDecision` can only report what the engine decided, so a request refused
 * before a decision existed was previously invisible to it. These tests pin the
 * second stream — `onBoundaryEvent` — and, more importantly, pin the rules that
 * keep the two streams disjoint and keep the audit path incapable of changing
 * what a caller sees.
 *
 * Scenarios:
 *   B-1  TRUSTED_CONTEXT / UNTRUSTED_CONTEXT, emitted by the outer catch only
 *   B-2  TRUSTED_CONTEXT / MISSING_TENANT_ID
 *   B-3  STATE_LOAD / STATE_VERSION_MISSING
 *   B-4  NORMALIZATION / NORMALIZATION_FAILURE (thrown, and wrapped)
 *   B-5  PROVENANCE / PROVENANCE_CONFLICT carries fields and provenance
 *   B-6  DELEGATION / DELEGATION_INPUT_INVALID
 *   B-7  DELEGATION / DELEGATION_VERIFICATION_FAILED
 *   B-8  REPLAY / DELEGATION_REPLAY
 *   B-9  REPLAY / AUTHORIZATION_REPLAY
 *   B-10 REPLAY / REPLAY_STORE_UNAVAILABLE
 *   B-11 POLICY_EVALUATION / ENGINE_FAILURE
 *   B-12 POLICY_EVALUATION / AUTHORIZATION_MISSING
 *   B-13 AUTHORIZATION_VERIFICATION / AUTHORIZATION_VERIFICATION_FAILED
 *   B-14 AUTHORIZATION_VERIFICATION / INTENT_HASH_MISMATCH
 *   B-15 AUTHORIZATION_VERIFICATION / STATE_HASH_MISMATCH
 *   B-16 STATE_COMMIT / CAS_CONFLICT
 *   B-17 EXECUTION_GATE / UNCLASSIFIED (a deployment hook failed)
 *   B-18 main path: a callback failure is NOT a boundary rejection
 *   B-19 delegation path: a callback failure is NOT a boundary rejection
 *   B-20 a non-object throw surfaces unchanged, through the UNCLASSIFIED fallback
 *   B-21 a policy DENY is reported on onDecision and NEVER on onBoundaryEvent
 *   B-22 a conflict raised inside the normalizer emits once, not once per layer
 *   B-23 a throwing audit sink does not change what the caller receives
 *   B-24 the record carries no policyDecision; policyEvaluated carries the fact
 *   B-25 the guard behaves identically with no boundary hook configured
 *   B-28 a malformed DENY (invalid reasons) emits POLICY_EVALUATION / ENGINE_FAILURE, not a decision (#247)
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  createDelegation,
  intentHash,
  signAuthorizationEd25519,
} from "@oxdeai/core";
import type { AuthorizationV1, DelegationScope, DelegationV1, Intent, State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";
import { TEST_KEYSET, TEST_KEYPAIR, signAuth } from "./helpers/fixtures.js";

import { OxDeAIGuard } from "../guard.js";
import { createSecureGuard } from "../secureGuard.js";
import { createTrustedExecutionContext } from "../trustedContext.js";
import type { TrustedExecutionContext } from "../trustedContext.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import {
  OxDeAIAuthorizationError,
  OxDeAIDelegationError,
  OxDeAIDenyError,
  OxDeAINormalizationError,
  OxDeAIProvenanceConflictError,
} from "../errors.js";
import type { GuardBoundaryAuditEvent } from "../boundaryEvent.js";
import type { OxDeAIGuardConfig, ProposedAction, StateVersion } from "../types.js";
import type { ReplayStore } from "../replayStore.js";

// ── fixtures ──────────────────────────────────────────────────────────────────

const ENGINE_SECRET = "test-secret-must-be-at-least-32-chars!!";
const AGENT_ID = "agent-test-001";
const PRIVILEGED_AGENT_ID = "agent-admin-root";

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1",
    engine_secret: ENGINE_SECRET,
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_issuer: TEST_KEYSET.issuer,
    authorization_audience: "aud-test",
    authorization_ttl_seconds: 600,
    authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeState(agentId: string = AGENT_ID): State {
  return buildState({
    agent_id: agentId,
    allow_action_types: ["PROVISION", "PAYMENT", "PURCHASE", "ONCHAIN_TX"],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
}

function makeGuardConfig(overrides: Partial<OxDeAIGuardConfig> = {}): OxDeAIGuardConfig {
  let currentState = makeState();
  let currentVersion = 0;
  return {
    engine: makeEngine(),
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => {
      if (v !== currentVersion) return false;
      currentState = s;
      currentVersion++;
      return true;
    },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    ...overrides,
  };
}

const baseAction: ProposedAction = {
  name: "provision_gpu",
  args: { asset: "a100" },
  estimatedCost: 0.5,
  resourceType: "gpu",
  context: { agent_id: AGENT_ID, target: "gpu-pool" },
};

function makeContext(overrides: Partial<TrustedExecutionContext> = {}): TrustedExecutionContext {
  return createTrustedExecutionContext({
    principalId: "principal-1",
    agentId: AGENT_ID,
    adapterId: "adapter-http",
    depth: 0,
    ...overrides,
  });
}

/** A mock engine, for the result shapes a real PolicyEngine will not produce. */
function mockEngine(
  evaluatePure: (intent: Intent, state: State, at: number) => unknown,
  computeStateHash: (state: State) => string = () => "0".repeat(64)
): PolicyEngine {
  return { evaluatePure, computeStateHash } as unknown as PolicyEngine;
}

// ── delegation fixtures (mirrors guard.delegation.test.ts) ────────────────────

const T_NOW = Math.floor(Date.now() / 1000);
const PARENT_SCOPE: DelegationScope = { tools: ["provision_gpu"], max_amount: 1_000_000n };

function makeParentAuth(): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: TEST_KEYSET.issuer,
      audience: "agent-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "policy-1",
      decision: "ALLOW",
      issued_at: T_NOW - 60,
      expiry: T_NOW + 900,
      kid: "k1",
    },
    TEST_KEYPAIR.privateKey.toString()
  );
}

function makeDelegation(parentAuth: AuthorizationV1, expiry: number = T_NOW + 300): DelegationV1 {
  return createDelegation(
    parentAuth,
    {
      delegatee: "agent-B",
      issuer: TEST_KEYSET.issuer,
      scope: { tools: ["provision_gpu"], max_amount: 1_000_000n },
      expiry,
      kid: "k1",
    },
    TEST_KEYPAIR.privateKey.toString()
  );
}

function makeDelegationConfig(overrides: Partial<OxDeAIGuardConfig> = {}): OxDeAIGuardConfig {
  const state = makeState("agent-B");
  return {
    engine: makeEngine(),
    getState: () => ({ state, version: 0 }),
    setState: () => true,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "agent-A",
    ...overrides,
  };
}

const delegatedAction: ProposedAction = {
  name: "provision_gpu",
  args: { asset: "a100" },
  estimatedCost: 0,
  context: { agent_id: "agent-B", target: "gpu-pool" },
  timestampSeconds: T_NOW,
};

// ── collector ─────────────────────────────────────────────────────────────────

type Collector = {
  readonly events: GuardBoundaryAuditEvent[];
  readonly hook: (event: GuardBoundaryAuditEvent) => void;
};

function collect(): Collector {
  const events: GuardBoundaryAuditEvent[] = [];
  return { events, hook: (event) => { events.push(event); } };
}

/** Asserts exactly one event was emitted and returns it. */
function only(events: readonly GuardBoundaryAuditEvent[]): GuardBoundaryAuditEvent {
  assert.equal(events.length, 1, `expected exactly one boundary event, got ${events.length}`);
  return events[0]!;
}

/** Runs a call expected to reject and returns the thrown value. */
async function caught(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (err) {
    return err;
  }
  assert.fail("expected the guard to reject");
}

// ── B-1 / B-2: the secure prelude, reported by the outer catch ────────────────

test("B-1 an unbranded trusted context emits TRUSTED_CONTEXT / UNTRUSTED_CONTEXT", async () => {
  const audit = collect();
  const secure = createSecureGuard(
    makeGuardConfig({ onBoundaryEvent: audit.hook }),
    { tenancy: "single-tenant" }
  );

  const forged = {
    principalId: "principal-1",
    agentId: AGENT_ID,
    adapterId: "adapter-http",
    depth: 0,
  } as unknown as TrustedExecutionContext;

  const err = await caught(() => secure(forged, baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "TRUSTED_CONTEXT");
  assert.equal(event.boundaryFailure, "UNTRUSTED_CONTEXT");
  // The shared body was never entered, so nothing downstream can have happened.
  assert.equal(event.policyEvaluated, false);
  assert.equal(event.authorizationIssued, false);
  assert.equal(event.authorizationConsumed, false);
  assert.equal(event.delegationConsumed, false);
  assert.equal(event.stateCommitted, false);
  assert.equal(event.executionStarted, false);
  assert.equal(event.intentId, undefined);
});

test("B-2 a multi-tenant deployment without tenantId emits MISSING_TENANT_ID", async () => {
  const audit = collect();
  const secure = createSecureGuard(
    makeGuardConfig({ onBoundaryEvent: audit.hook }),
    { tenancy: "multi-tenant" }
  );

  const err = await caught(() => secure(makeContext(), baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "TRUSTED_CONTEXT");
  assert.equal(event.boundaryFailure, "MISSING_TENANT_ID");
});

// ── B-3 .. B-17: one per reachable stage / category pairing ───────────────────

test("B-3 a state store returning no version emits STATE_LOAD / STATE_VERSION_MISSING", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({
      getState: () => ({ state: makeState(), version: undefined as unknown as StateVersion }),
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "STATE_LOAD");
  assert.equal(event.boundaryFailure, "STATE_VERSION_MISSING");
  assert.equal(event.intentId, undefined, "normalization has not run yet");
});

test("B-4 a normalization failure emits NORMALIZATION / NORMALIZATION_FAILURE", async () => {
  // (a) the default normalizer rejecting an incomplete action.
  const thrown = collect();
  const guard = OxDeAIGuard(makeGuardConfig({ onBoundaryEvent: thrown.hook }));
  const err = await caught(() =>
    guard({ name: "provision_gpu", args: {}, context: {} }, async () => "done")
  );
  assert.ok(err instanceof OxDeAINormalizationError);
  const event = only(thrown.events);
  assert.equal(event.stage, "NORMALIZATION");
  assert.equal(event.boundaryFailure, "NORMALIZATION_FAILURE");

  // (b) a custom normalizer throwing something unexpected, which the guard
  //     wraps. The wrapper is what the caller sees, and it is what is reported.
  const wrapped = collect();
  const guard2 = OxDeAIGuard(
    makeGuardConfig({
      mapActionToIntent: () => { throw new Error("normalizer exploded"); },
      onBoundaryEvent: wrapped.hook,
    })
  );
  const err2 = await caught(() => guard2(baseAction, async () => "done"));
  assert.ok(err2 instanceof OxDeAINormalizationError);
  const event2 = only(wrapped.events);
  assert.equal(event2.stage, "NORMALIZATION");
  assert.equal(event2.boundaryFailure, "NORMALIZATION_FAILURE");
});

test("B-5 a provenance conflict emits PROVENANCE / PROVENANCE_CONFLICT with its evidence", async () => {
  const audit = collect();
  const secure = createSecureGuard(
    makeGuardConfig({ onBoundaryEvent: audit.hook }),
    { tenancy: "single-tenant" }
  );

  const substituted: ProposedAction = {
    ...baseAction,
    context: { ...baseAction.context, agent_id: PRIVILEGED_AGENT_ID },
  };

  const err = await caught(() => secure(makeContext(), substituted, async () => "done"));
  assert.ok(err instanceof OxDeAIProvenanceConflictError);

  const event = only(audit.events);
  assert.equal(event.stage, "PROVENANCE");
  assert.equal(event.boundaryFailure, "PROVENANCE_CONFLICT");
  assert.deepEqual(event.conflictingFields, ["agent_id"]);
  // The record reuses the reconciliation vocabulary, not an opaque string map:
  // an audit reader parses one provenance type across both streams.
  assert.equal(event.provenance?.["agent_id"], "conflict");
  assert.equal(event.policyEvaluated, false, "a conflict is refused before evaluation");
});

test("B-6 incomplete delegation input emits DELEGATION / DELEGATION_INPUT_INVALID", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(makeDelegationConfig({ onBoundaryEvent: audit.hook }));

  const err = await caught(() =>
    guard(delegatedAction, async () => "done", {
      delegation: {
        delegation: null as unknown as DelegationV1,
        parentAuth: null as unknown as AuthorizationV1,
        parentScope: {},
      },
    })
  );
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "DELEGATION");
  assert.equal(event.boundaryFailure, "DELEGATION_INPUT_INVALID");
});

test("B-7 a failed delegation chain emits DELEGATION / DELEGATION_VERIFICATION_FAILED", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(makeDelegationConfig({ onBoundaryEvent: audit.hook }));
  const parentAuth = makeParentAuth();
  const expired = makeDelegation(parentAuth, T_NOW - 1);

  const err = await caught(() =>
    guard(delegatedAction, async () => "done", {
      delegation: { delegation: expired, parentAuth, parentScope: PARENT_SCOPE },
    })
  );
  assert.ok(err instanceof OxDeAIDelegationError);

  const event = only(audit.events);
  assert.equal(event.stage, "DELEGATION");
  assert.equal(event.boundaryFailure, "DELEGATION_VERIFICATION_FAILED");
  assert.equal(event.policyEvaluated, false, "the delegation path never calls the engine");
});

test("B-8 a replayed delegation emits REPLAY / DELEGATION_REPLAY", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(makeDelegationConfig({ onBoundaryEvent: audit.hook }));
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const input = { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } };

  await guard(delegatedAction, async () => "first", input);
  assert.deepEqual(audit.events, [], "a permitted call is not a boundary rejection");

  const err = await caught(() => guard(delegatedAction, async () => "second", input));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "REPLAY");
  assert.equal(event.boundaryFailure, "DELEGATION_REPLAY");
  assert.equal(
    event.delegationConsumed,
    false,
    "the replayed id was consumed by the FIRST call, not by this one"
  );
});

test("B-9 a replayed authorization emits REPLAY / AUTHORIZATION_REPLAY", async () => {
  const audit = collect();
  const store: ReplayStore = { consumeAuthId: async () => false };
  const guard = OxDeAIGuard(makeGuardConfig({ replayStore: store, onBoundaryEvent: audit.hook }));

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "REPLAY");
  assert.equal(event.boundaryFailure, "AUTHORIZATION_REPLAY");
  assert.equal(event.policyEvaluated, true, "the engine ran before replay was checked");
  assert.equal(event.authorizationIssued, true);
  assert.equal(event.authorizationConsumed, false, "a replayed id is not consumed by this call");
  assert.equal(event.stateCommitted, false);
  assert.equal(event.executionStarted, false);
  assert.ok(event.intentId, "the intent had been normalized by this point");
});

test("B-10 an unavailable replay store emits REPLAY / REPLAY_STORE_UNAVAILABLE", async () => {
  const audit = collect();
  const store: ReplayStore = {
    consumeAuthId: async () => { throw new Error("redis down"); },
  };
  const guard = OxDeAIGuard(makeGuardConfig({ replayStore: store, onBoundaryEvent: audit.hook }));

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "REPLAY");
  assert.equal(event.boundaryFailure, "REPLAY_STORE_UNAVAILABLE");
});

test("B-11 an engine that throws emits POLICY_EVALUATION / ENGINE_FAILURE", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({
      engine: mockEngine(() => { throw new Error("engine unavailable"); }),
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "POLICY_EVALUATION");
  assert.equal(event.boundaryFailure, "ENGINE_FAILURE");
  assert.equal(
    event.policyEvaluated,
    false,
    "an engine that threw did not evaluate; the flag must not claim it did"
  );
});

test("B-12 ALLOW without an artifact emits POLICY_EVALUATION / AUTHORIZATION_MISSING", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({
      engine: mockEngine((_intent, state) => ({ decision: "ALLOW", reasons: [], nextState: state })),
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "POLICY_EVALUATION");
  assert.equal(event.boundaryFailure, "AUTHORIZATION_MISSING");
  assert.equal(event.policyEvaluated, true);
  assert.equal(event.authorizationIssued, false);
});

test("B-13 a failed verifier emits AUTHORIZATION_VERIFICATION / AUTHORIZATION_VERIFICATION_FAILED", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({
      // Correctly signed, but issued to a different audience than this guard
      // instance protects.
      engine: mockEngine((_intent, state) => ({
        decision: "ALLOW",
        reasons: [],
        nextState: state,
        authorization: signAuth({ audience: "aud-somebody-else" }),
      })),
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "AUTHORIZATION_VERIFICATION");
  assert.equal(event.boundaryFailure, "AUTHORIZATION_VERIFICATION_FAILED");
  assert.equal(event.authorizationIssued, true);
  assert.equal(event.authorizationConsumed, true, "the id was consumed before verification");
});

test("B-14 an unbound intent emits AUTHORIZATION_VERIFICATION / INTENT_HASH_MISMATCH", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({
      // A verifiable authorization committing to some other intent.
      engine: mockEngine((_intent, state) => ({
        decision: "ALLOW",
        reasons: [],
        nextState: state,
        authorization: signAuth({ intent_hash: "9".repeat(64) }),
      })),
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "AUTHORIZATION_VERIFICATION");
  assert.equal(event.boundaryFailure, "INTENT_HASH_MISMATCH");
});

test("B-15 an unbound state emits AUTHORIZATION_VERIFICATION / STATE_HASH_MISMATCH", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({
      // Intent binding holds; the committed state snapshot does not.
      engine: mockEngine((intent, state) => ({
        decision: "ALLOW",
        reasons: [],
        nextState: state,
        authorization: signAuth({ intent_hash: intentHash(intent), state_hash: "7".repeat(64) }),
      })),
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "AUTHORIZATION_VERIFICATION");
  assert.equal(event.boundaryFailure, "STATE_HASH_MISMATCH");
  assert.equal(event.stateCommitted, false, "the binding is checked before the commit");
});

test("B-16 a lost CAS race emits STATE_COMMIT / CAS_CONFLICT", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({ setState: () => false, onBoundaryEvent: audit.hook })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const event = only(audit.events);
  assert.equal(event.stage, "STATE_COMMIT");
  assert.equal(event.boundaryFailure, "CAS_CONFLICT");
  assert.equal(event.authorizationConsumed, true);
  assert.equal(event.stateCommitted, false);
  assert.equal(event.executionStarted, false, "a lost race blocks side effects");
});

test("B-17 a failing deployment hook emits EXECUTION_GATE / UNCLASSIFIED", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({
      beforeExecute: () => { throw new Error("pre-flight check failed"); },
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.equal((err as Error).message, "pre-flight check failed", "the hook's error is not wrapped");

  const event = only(audit.events);
  assert.equal(event.stage, "EXECUTION_GATE");
  assert.equal(
    event.boundaryFailure,
    "UNCLASSIFIED",
    "an unannotated escape is reported honestly, never silently dropped"
  );
  assert.equal(event.stateCommitted, true, "the commit had already happened");
  assert.equal(event.executionStarted, false, "the gate never opened");
});

// ── B-18 / B-19: executionStarted precedes the callback, at BOTH sites ────────

test("B-18 main path: a failure inside the protected callback is not a boundary rejection", async () => {
  const audit = collect();
  let commits = 0;
  let currentState = makeState();
  let currentVersion = 0;

  const guard = OxDeAIGuard(
    makeGuardConfig({
      getState: () => ({ state: currentState, version: currentVersion }),
      setState: (s, v) => {
        commits++;
        // The second call loses the CAS race — the control below.
        if (commits > 1 || v !== currentVersion) return false;
        currentState = s;
        currentVersion++;
        return true;
      },
      onBoundaryEvent: audit.hook,
    })
  );

  const boom = new Error("the side effect failed");
  const err = await caught(() => guard(baseAction, async () => { throw boom; }));

  assert.equal(err, boom, "the callback's own error reaches the caller unchanged");
  assert.deepEqual(
    audit.events,
    [],
    "past the execution gate the guard has already permitted the action: a callback " +
      "failure is the caller's, and reporting it would make the audit stream claim " +
      "the guard refused something it allowed"
  );

  // Control, on the SAME guard instance and the SAME hook: a rejection raised
  // before the gate still emits. Without this, the assertion above would also
  // pass if the hook were simply never wired.
  const err2 = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err2 instanceof OxDeAIAuthorizationError);
  const event = only(audit.events);
  assert.equal(event.boundaryFailure, "CAS_CONFLICT");
  assert.equal(event.executionStarted, false);
});

test("B-19 delegation path: a failure inside the protected callback is not a boundary rejection", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(makeDelegationConfig({ onBoundaryEvent: audit.hook }));
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const input = { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } };

  const boom = new Error("the delegated side effect failed");
  const err = await caught(() => guard(delegatedAction, async () => { throw boom; }, input));

  assert.equal(err, boom, "the callback's own error reaches the caller unchanged");
  assert.deepEqual(
    audit.events,
    [],
    "the delegation path opens its own execution gate and must honour it identically"
  );

  // Control, on the SAME guard instance and the SAME hook: replaying the now
  // consumed delegation is refused before the gate, and does emit.
  const err2 = await caught(() => guard(delegatedAction, async () => "done", input));
  assert.ok(err2 instanceof OxDeAIAuthorizationError);
  const event = only(audit.events);
  assert.equal(event.boundaryFailure, "DELEGATION_REPLAY");
  assert.equal(event.executionStarted, false);
});

// ── B-20: non-object throws ──────────────────────────────────────────────────

test("B-20 a non-object throw surfaces unchanged and reports UNCLASSIFIED", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({
      // `throw "boom"` is legal, and a third-party callback may do it. The
      // audit path keys de-duplication on the thrown value, so it must not
      // assume that value can key a WeakSet.
      getState: () => { throw "boom"; },
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.equal(err instanceof Error, false, "it is not replaced by a TypeError from the audit path");
  assert.equal(err, "boom", "and the original rejection reaches the caller");

  const event = only(audit.events);
  assert.equal(event.stage, "STATE_LOAD");
  assert.equal(event.boundaryFailure, "UNCLASSIFIED");
});

test("B-20b a non-object throw on the secure path is still reported exactly once", async () => {
  const audit = collect();
  const secure = createSecureGuard(
    makeGuardConfig({
      getState: () => { throw "boom"; },
      onBoundaryEvent: audit.hook,
    }),
    { tenancy: "single-tenant" }
  );

  const err = await caught(() => secure(makeContext(), baseAction, async () => "done"));
  assert.equal(err, "boom");

  // Two nested catches see this rejection and it cannot be tracked by identity,
  // so only the lifecycle can stop the outer one from reporting it a second time.
  const event = only(audit.events);
  assert.equal(event.boundaryFailure, "UNCLASSIFIED");
});

test("B-20c a normalizer that throws a string still yields the guard's own error", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({
      mapActionToIntent: () => { throw "boom"; },
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAINormalizationError, "the pre-existing wrapping is unchanged");
  assert.match((err as Error).message, /boom/);

  const event = only(audit.events);
  assert.equal(event.boundaryFailure, "NORMALIZATION_FAILURE");
});

// ── B-21: DENY belongs to the other stream ───────────────────────────────────

test("B-21 a policy DENY is reported on onDecision and never on onBoundaryEvent", async () => {
  const audit = collect();
  const decisions: string[] = [];
  const denied: State = { ...makeState(), kill_switch: { global: true, agents: {} } };

  const guard = OxDeAIGuard(
    makeGuardConfig({
      getState: () => ({ state: denied, version: 0 }),
      onDecision: ({ decision }) => { decisions.push(decision); },
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIDenyError);

  assert.deepEqual(decisions, ["DENY"]);
  assert.deepEqual(
    audit.events,
    [],
    "a denial is a decision, not a boundary rejection: reporting it on both " +
      "streams would double-count every DENY in an audit pipeline"
  );
});

// ── B-22: one rejection, one event, however many layers see it ───────────────

test("B-22 a conflict raised inside the normalizer is emitted once, not once per layer", async () => {
  const audit = collect();
  const secure = createSecureGuard(
    makeGuardConfig({ onBoundaryEvent: audit.hook }),
    { tenancy: "single-tenant" }
  );

  const substituted: ProposedAction = {
    ...baseAction,
    context: { ...baseAction.context, agent_id: PRIVILEGED_AGENT_ID },
  };

  await caught(() => secure(makeContext(), substituted, async () => "done"));

  // The conflict is raised inside the injected normalizer, so the shared body's
  // catch and the secure wrapper's catch both see the same error object.
  assert.equal(audit.events.length, 1, "two nested catches must not double-report");
  assert.equal(audit.events[0]!.boundaryFailure, "PROVENANCE_CONFLICT");
});

test("B-22b a custom normalizer's own provenance conflict is classified the same way", async () => {
  // The classification lives at the shared body's throw site, so it does not
  // depend on the secure wrapper having produced the conflict.
  const audit = collect();
  const guard = OxDeAIGuard(
    makeGuardConfig({
      mapActionToIntent: () => {
        throw new OxDeAIProvenanceConflictError(["tool"], { tool: "conflict" });
      },
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIProvenanceConflictError);

  const event = only(audit.events);
  assert.equal(event.stage, "PROVENANCE");
  assert.equal(event.boundaryFailure, "PROVENANCE_CONFLICT");
  assert.deepEqual(event.conflictingFields, ["tool"]);
});

// ── B-23: the audit sink cannot change the outcome ───────────────────────────

test("B-23 a throwing audit sink does not change what the caller receives", async () => {
  const guard = OxDeAIGuard(
    makeGuardConfig({
      setState: () => false,
      onBoundaryEvent: () => { throw new Error("audit sink is down"); },
    })
  );

  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError, "the ORIGINAL guard error, not the sink's");
  assert.match((err as Error).message, /concurrent modification/);
});

test("B-23b a rejecting async audit sink does not change what the caller receives", async () => {
  const secure = createSecureGuard(
    makeGuardConfig({
      onBoundaryEvent: async () => { throw new Error("audit sink is down"); },
    }),
    { tenancy: "multi-tenant" }
  );

  const err = await caught(() => secure(makeContext(), baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);
  assert.match((err as Error).message, /multi-tenant/);
});

// ── B-24: what the record deliberately does not carry ────────────────────────

test("B-24 the record carries no policyDecision; policyEvaluated carries the fact", async () => {
  // A boundary event never carries a DENY: a denial is an OxDeAIDenyError, which
  // is reported on onDecision and returns early from emission (pinned by B-21).
  // "ALLOW" would therefore be the only value the field could ever hold, and it
  // would hold it exactly when policyEvaluated is already true — so the field is
  // omitted rather than frozen into the public shape carrying one value.
  const after = collect();
  const guard = OxDeAIGuard(makeGuardConfig({ setState: () => false, onBoundaryEvent: after.hook }));
  await caught(() => guard(baseAction, async () => "done"));
  const afterAllow = only(after.events);

  assert.equal(Object.prototype.hasOwnProperty.call(afterAllow, "policyDecision"), false);
  assert.equal(afterAllow.policyEvaluated, true);
  assert.equal(afterAllow.authorizationIssued, true);

  const before = collect();
  const guard2 = OxDeAIGuard(
    makeGuardConfig({
      getState: () => ({ state: makeState(), version: undefined as unknown as StateVersion }),
      onBoundaryEvent: before.hook,
    })
  );
  await caught(() => guard2(baseAction, async () => "done"));
  const beforeEvaluation = only(before.events);

  assert.equal(Object.prototype.hasOwnProperty.call(beforeEvaluation, "policyDecision"), false);
  assert.equal(
    beforeEvaluation.policyEvaluated,
    false,
    "policyEvaluated is what separates a pre-evaluation refusal from a post-ALLOW one"
  );
});

// ── B-25: the hook is optional ───────────────────────────────────────────────

test("B-25 the guard behaves identically with no boundary hook configured", async () => {
  const guard = OxDeAIGuard(makeGuardConfig({ setState: () => false }));
  const err = await caught(() => guard(baseAction, async () => "done"));
  assert.ok(err instanceof OxDeAIAuthorizationError);

  const permitting = OxDeAIGuard(makeGuardConfig());
  assert.equal(await permitting(baseAction, async () => "executed"), "executed");
});

test("B-25b a permitted call emits nothing on the boundary stream", async () => {
  const audit = collect();
  const guard = OxDeAIGuard(makeGuardConfig({ onBoundaryEvent: audit.hook }));

  const result = await guard(baseAction, async () => "executed");

  assert.equal(result, "executed");
  assert.deepEqual(audit.events, [], "the boundary stream reports rejections only");
});

// ── the reconciliation path still behaves as before ──────────────────────────

test("B-26 the secure path still reports provenance on onDecision for an ALLOW", async () => {
  const audit = collect();
  const records: Array<Record<string, unknown>> = [];
  const secure = createSecureGuard(
    makeGuardConfig({
      onDecision: (r) => { records.push(r as unknown as Record<string, unknown>); },
      onBoundaryEvent: audit.hook,
    }),
    { tenancy: "single-tenant" }
  );

  const result = await secure(makeContext({ tool: "provision_gpu" }), baseAction, async () => "ok");

  assert.equal(result, "ok");
  assert.equal(records.length, 1, "the decision stream is unchanged");
  assert.deepEqual(audit.events, []);
  const provenance = records[0]?.["provenance"] as Record<string, string> | undefined;
  assert.equal(provenance?.["agent_id"], "matched");
});

test("B-27 defaultNormalizeAction is unchanged by the audit wiring", () => {
  const intent: Intent = defaultNormalizeAction(baseAction);
  assert.equal(intent.agent_id, AGENT_ID);
  assert.equal(intent.amount, 500_000n);
});

// ── B-28: malformed DENY is an engine-contract violation, not a decision (#247) ──

test("B-28 a malformed DENY (invalid reasons) emits POLICY_EVALUATION / ENGINE_FAILURE, not a decision", async () => {
  const audit = collect();
  let onDecisionCalled = false;
  let executed = false;
  const guard = OxDeAIGuard(
    makeGuardConfig({
      engine: mockEngine(() => ({ decision: "DENY", reasons: undefined })),
      onDecision: () => { onDecisionCalled = true; },
      onBoundaryEvent: audit.hook,
    })
  );

  const err = await caught(() => guard(baseAction, async () => { executed = true; return "done"; }));
  assert.ok(err instanceof OxDeAIAuthorizationError);
  assert.ok(!(err instanceof OxDeAIDenyError), "a malformed DENY must not surface as a valid OxDeAIDenyError");
  assert.ok(!onDecisionCalled, "a malformed DENY must never be reported on onDecision as a synthetic decision");
  assert.ok(!executed, "the protected callback must not execute on a malformed DENY");

  const event = only(audit.events);
  assert.equal(event.stage, "POLICY_EVALUATION");
  assert.equal(event.boundaryFailure, "ENGINE_FAILURE");
  assert.equal(
    event.policyEvaluated,
    true,
    "the engine call returned (unlike B-11, where it threw); only its DENY payload was malformed"
  );
});
