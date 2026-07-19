// SPDX-License-Identifier: Apache-2.0
/**
 * trusted-time-integration.test.ts
 *
 * #184: trusted-time freshness wired into PolicyEngine as a mandatory,
 * audited pre-module gate (docs/spec/core/trusted-time-v1.md §6-§7).
 *
 * These tests exercise the integration boundary only — evaluate/evaluatePure
 * with the new required `evaluationTime` parameter and the freshness gate's
 * interaction with the module pipeline, audit trail, and constructor/call
 * preconditions. `verifyTrustedTime` itself is unit-tested in
 * verify.trusted-time.test.ts; issuance/expiry derivation is intentionally
 * untouched and guarded by property.decision.test.ts's D-6 tripwire.
 *
 * "No module ran" is proven the way the repository's own tooling requires:
 * a positive control (collect-all mode against a state where BOTH Replay and
 * Velocity would deny) shows the harness detects pipeline invocation, and the
 * absence of those same reasons on a non-fresh intent against the identical
 * state — combined with that positive control — proves runDecisionModules
 * was never called. Absence of nextState / vacuous DENY shape is not used as
 * proof of anything, per the harness's own documented pitfall.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import type { State } from "../types/state.js";
import type { Intent } from "../types/intent.js";

const AGENT = "agent-1";
const T0 = 1_730_000_000;
const MAX_SKEW = 300;
const MAX_AGE = 300;

function makeEngine(overrides?: Record<string, unknown>): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1-tt",
    engine_secret: "trusted-time-integration-secret-32ch!",
    authorization_ttl_seconds: 60,
    deny_mode: "fail-fast",
    maxClockSkewSeconds: MAX_SKEW,
    maxIntentAgeSeconds: MAX_AGE,
    ...overrides,
  } as ConstructorParameters<typeof PolicyEngine>[0]);
}

/** Fresh, uncontended state: no retained nonces, empty velocity counters. */
function freshState(overrides?: Partial<State>): State {
  return {
    policy_version: "v1-tt",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["wallet"], targets: ["user_1"] },
    budget: { budget_limit: { [AGENT]: 1_000_000_000n }, spent_in_period: { [AGENT]: 0n } },
    max_amount_per_action: { [AGENT]: 1_000_000_000n },
    velocity: { config: { window_seconds: 60, max_actions: 1000 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { [AGENT]: 10 }, active: {}, active_auths: {} },
    recursion: { max_depth: { [AGENT]: 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { [AGENT]: 1000 }, calls: {} },
    ...overrides,
  } as State;
}

/**
 * State where BOTH Replay and Velocity would deny a fresh intent with
 * nonce "7": nonce "7" is already retained, and the velocity window is
 * already saturated (count 1, max_actions 1 → the next action tips it over).
 */
function contendedState(): State {
  return freshState({
    velocity: {
      config: { window_seconds: 60, max_actions: 1 },
      counters: { [AGENT]: { window_start: T0, count: 1 } },
    },
    replay: {
      window_seconds: 3600,
      max_nonces_per_agent: 256,
      nonces: { [AGENT]: [{ nonce: "7", ts: T0 }] },
    },
  });
}

function makeIntent(overrides?: Partial<Intent>): Intent {
  return {
    intent_id: "tt-intent-1",
    agent_id: AGENT,
    action_type: "PAYMENT",
    amount: 100n,
    asset: "wallet",
    target: "user_1",
    timestamp: T0,
    metadata_hash: "0".repeat(64),
    nonce: 1n,
    signature: "sig",
    depth: 0,
    type: "EXECUTE",
    ...overrides,
  } as Intent;
}

// ── 1. Fresh ALLOW path unchanged ───────────────────────────────────────────

test("fresh ALLOW: authorization present, nextState present, existing semantics unchanged", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(makeIntent(), freshState(), T0);
  assert.equal(out.decision, "ALLOW");
  assert.ok("authorization" in out && out.authorization);
  assert.ok("nextState" in out && out.nextState);
});

// ── 2 & 3. Future / stale denial shape ──────────────────────────────────────

test("future-dated intent → exactly DENY/INTENT_FRESHNESS_FUTURE", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(makeIntent({ timestamp: T0 + MAX_SKEW + 1 }), freshState(), T0);
  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_FRESHNESS_FUTURE"] });
});

test("stale intent → exactly DENY/INTENT_STALE", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(makeIntent({ timestamp: T0 - MAX_AGE - 1 }), freshState(), T0);
  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_STALE"] });
});

// ── 4-7. Positive control + no-invocation proofs (EXECUTE) ─────────────────

test("EXECUTE collect-all positive control: fresh intent against contended state includes REPLAY_NONCE and VELOCITY_EXCEEDED", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(
    makeIntent({ nonce: 7n, timestamp: T0 }),
    contendedState(),
    T0,
    { mode: "collect-all" }
  );
  assert.equal(out.decision, "DENY");
  if (out.decision !== "DENY") return;
  assert.ok(out.reasons.includes("REPLAY_NONCE"), `expected REPLAY_NONCE, got ${JSON.stringify(out.reasons)}`);
  assert.ok(out.reasons.includes("VELOCITY_EXCEEDED"), `expected VELOCITY_EXCEEDED, got ${JSON.stringify(out.reasons)}`);
});

test("EXECUTE future no-invocation proof: future-dated intent against the SAME contended state returns exactly INTENT_FRESHNESS_FUTURE", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(
    makeIntent({ nonce: 7n, timestamp: T0 + MAX_SKEW + 1 }),
    contendedState(),
    T0,
    { mode: "collect-all" }
  );
  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_FRESHNESS_FUTURE"] });
});

test("EXECUTE stale no-invocation proof: stale intent against the SAME contended state returns exactly INTENT_STALE", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(
    makeIntent({ nonce: 7n, timestamp: T0 - MAX_AGE - 1 }),
    contendedState(),
    T0,
    { mode: "collect-all" }
  );
  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_STALE"] });
});

// ── 7. RELEASE control + no-invocation proof ────────────────────────────────
// RELEASE_MODULES = [KillSwitchModule, ReplayModule, ConcurrencyModule] — no
// VelocityModule, so velocity ordering is EXECUTE-only (see module boundary
// notes). Fail-fast is sufficient here: ReplayModule precedes ConcurrencyModule
// in RELEASE_MODULES, so a retained-nonce DENY surfaces before any concurrency
// check runs, regardless of authorization_id validity.

test("RELEASE control: fresh RELEASE intent with retained nonce → REPLAY_NONCE", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(
    makeIntent({ nonce: 7n, timestamp: T0, type: "RELEASE", authorization_id: "irrelevant" }),
    contendedState(),
    T0
  );
  assert.deepEqual(out, { decision: "DENY", reasons: ["REPLAY_NONCE"] });
});

test("RELEASE no-invocation proof: non-fresh RELEASE intent with the SAME retained-nonce state returns only its freshness reason", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(
    makeIntent({ nonce: 7n, timestamp: T0 + MAX_SKEW + 1, type: "RELEASE", authorization_id: "irrelevant" }),
    contendedState(),
    T0
  );
  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_FRESHNESS_FUTURE"] });
});

// ── 8 & 9. Fresh replay / velocity behavior unchanged (fail-fast) ──────────

test("fresh replay behavior unchanged: fresh intent with retained nonce in fail-fast → REPLAY_NONCE", () => {
  const engine = makeEngine();
  const state = freshState({
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: { [AGENT]: [{ nonce: "7", ts: T0 }] } },
  });
  const out = engine.evaluatePure(makeIntent({ nonce: 7n, timestamp: T0 }), state, T0);
  assert.deepEqual(out, { decision: "DENY", reasons: ["REPLAY_NONCE"] });
});

test("fresh velocity behavior unchanged: fresh EXECUTE intent against saturated velocity state in fail-fast → VELOCITY_EXCEEDED", () => {
  const engine = makeEngine();
  const state = freshState({
    velocity: { config: { window_seconds: 60, max_actions: 1 }, counters: { [AGENT]: { window_start: T0, count: 1 } } },
  });
  const out = engine.evaluatePure(makeIntent({ timestamp: T0 }), state, T0);
  assert.deepEqual(out, { decision: "DENY", reasons: ["VELOCITY_EXCEEDED"] });
});

// ── 10. Invalid evaluationTime trusted precondition ─────────────────────────

test("invalid evaluationTime throws before the try block — no decision, no audit event", () => {
  const badValues: unknown[] = [NaN, Infinity, 1.5, -1, Number.MAX_SAFE_INTEGER + 1, undefined];
  for (const bad of badValues) {
    const engine = makeEngine();
    assert.throws(
      () => engine.evaluatePure(makeIntent(), freshState(), bad as number),
      /evaluationTime/,
      `expected throw for evaluationTime=${String(bad)}`
    );
    const events = engine.audit.snapshot();
    assert.equal(events.length, 0, `expected no audit events for evaluationTime=${String(bad)}, got ${JSON.stringify(events.map((e) => e.type))}`);
  }
});

// ── 11. Invalid constructor configuration ───────────────────────────────────

test("invalid maxClockSkewSeconds prevents engine construction", () => {
  const badValues: unknown[] = [NaN, Infinity, 1.5, -1, Number.MAX_SAFE_INTEGER + 1, undefined];
  for (const bad of badValues) {
    assert.throws(
      () => makeEngine({ maxClockSkewSeconds: bad }),
      /maxClockSkewSeconds/,
      `expected constructor throw for maxClockSkewSeconds=${String(bad)}`
    );
  }
});

test("invalid maxIntentAgeSeconds prevents engine construction", () => {
  const badValues: unknown[] = [NaN, Infinity, 1.5, -1, Number.MAX_SAFE_INTEGER + 1, undefined];
  for (const bad of badValues) {
    assert.throws(
      () => makeEngine({ maxIntentAgeSeconds: bad }),
      /maxIntentAgeSeconds/,
      `expected constructor throw for maxIntentAgeSeconds=${String(bad)}`
    );
  }
});

// ── 12 & 13. Malformed-timestamp reachability classes ───────────────────────
//
// Class A: values rejected during intent hashing, before audit emission —
// NaN, Infinity, non-integer numbers, and unsafe-magnitude integers. These
// throw inside canonicalizeToJson (FLOAT_NOT_ALLOWED / UNSAFE_INTEGER_NUMBER)
// before evaluatePure ever reaches INTENT_RECEIVED or verifyTrustedTime.
// Unchanged by #184 — preserved exactly, per the frozen decisions.
//
// Reachable malformed values (not Class A): a canonicalizable value that
// fails verifyTrustedTime's own protocol-seconds predicate instead. Both
// negative safe integers (-5) and non-number values that canonicalize
// successfully (a string) fall in this bucket: they clear the hashing
// boundary, reach INTENT_RECEIVED, and are only then denied by the freshness
// gate with an audited STATE_INVALID. This is the concrete vulnerability
// #184 closes — see the final implementation report for the measured
// baseline (pre-#184: intent.timestamp = -5 returned ALLOW and minted an
// authorization with issued_at: -5, expiry: 55).
//
// Note: an earlier draft of the implementation plan for this issue listed
// `"1000" as any` as a Class-A example. Measured directly against
// intentHash(), a string value does NOT throw during canonicalization (it
// hits the plain `typeof value === "string"` branch and serializes
// successfully), so it is a reachable malformed value, not Class A. The test
// below asserts the measured behavior, not that assumption.

test("Class A: non-canonicalizable timestamps preserve existing DENY/INTERNAL_ERROR, no audit events", () => {
  const badTimestamps: unknown[] = [1.5, NaN, Infinity, 2 ** 53];
  for (const bad of badTimestamps) {
    const engine = makeEngine();
    const out = engine.evaluatePure(makeIntent({ timestamp: bad as number }), freshState(), T0);
    assert.deepEqual(out, { decision: "DENY", reasons: ["INTERNAL_ERROR"] }, `timestamp=${String(bad)}`);
    assert.equal(engine.audit.snapshot().length, 0, `expected no audit events for timestamp=${String(bad)}`);
  }
});

test("reachable malformed timestamp: intent.timestamp = -5 (negative safe integer) → audited DENY/STATE_INVALID", () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(makeIntent({ timestamp: -5 }), freshState(), T0);
  assert.deepEqual(out, { decision: "DENY", reasons: ["STATE_INVALID"] });

  const types = engine.audit.snapshot().map((e) => e.type);
  assert.deepEqual(types, ["INTENT_RECEIVED", "DECISION"]);
});

test('reachable malformed timestamp: intent.timestamp = "1000" as any (canonicalizable non-number) → audited DENY/STATE_INVALID, not Class A', () => {
  const engine = makeEngine();
  const out = engine.evaluatePure(makeIntent({ timestamp: "1000" as unknown as number }), freshState(), T0);
  assert.deepEqual(out, { decision: "DENY", reasons: ["STATE_INVALID"] });
  assert.deepEqual(engine.audit.snapshot().map((e) => e.type), ["INTENT_RECEIVED", "DECISION"]);
});

// ── 14. Determinism ──────────────────────────────────────────────────────────

test("determinism: identical intent/state/evaluationTime/config/mode → identical decision, reasons, audit sequence, authorization and nextState", () => {
  const engine1 = makeEngine();
  const engine2 = makeEngine();
  const intent = makeIntent({ nonce: 42n });

  const out1 = engine1.evaluatePure(intent, freshState(), T0, { mode: "collect-all" });
  const out2 = engine2.evaluatePure(intent, freshState(), T0, { mode: "collect-all" });

  assert.equal(out1.decision, out2.decision);
  assert.deepEqual(out1.decision === "DENY" ? out1.reasons : [], out2.decision === "DENY" ? out2.reasons : []);
  assert.deepEqual(
    engine1.audit.snapshot().map((e) => e.type),
    engine2.audit.snapshot().map((e) => e.type)
  );
  if (out1.decision === "ALLOW" && out2.decision === "ALLOW") {
    assert.equal(out1.authorization.auth_id, out2.authorization.auth_id);
    assert.equal(out1.authorization.issued_at, out2.authorization.issued_at);
    assert.equal(engine1.computeStateHash(out1.nextState), engine2.computeStateHash(out2.nextState));
  }
});

// ── 15. Freshness-DENY audit shape + checkpoint behavior ────────────────────

test("freshness-DENY audit shape: INTENT_RECEIVED then DECISION, in order, with checkpoint behavior preserved", () => {
  const engine = makeEngine({ checkpoint_every_n_events: 1 });
  const out = engine.evaluatePure(makeIntent({ timestamp: T0 + MAX_SKEW + 1 }), freshState(), T0);
  assert.equal(out.decision, "DENY");

  const events = engine.audit.snapshot();
  const types = events.map((e) => e.type);
  assert.ok(types.includes("INTENT_RECEIVED"));
  assert.ok(types.includes("DECISION"));
  assert.ok(types.indexOf("INTENT_RECEIVED") < types.indexOf("DECISION"));
  // checkpoint_every_n_events: 1 — every emitted event triggers a checkpoint,
  // exactly mirroring existing module-pipeline DENY checkpoint behavior.
  assert.ok(types.includes("STATE_CHECKPOINT"), `expected STATE_CHECKPOINT, got ${JSON.stringify(types)}`);

  const decisionEvent = events.find((e) => e.type === "DECISION") as { reasons?: string[] } | undefined;
  assert.deepEqual(decisionEvent?.reasons, ["INTENT_FRESHNESS_FUTURE"]);
});

// ── 16. Existing issuance tripwire ──────────────────────────────────────────
// D-6 in property.decision.test.ts already asserts
// authorization.issued_at === intent.timestamp and is left unmodified by
// #184 — re-asserted here at the integration-test level as a second,
// independent tripwire against accidental scope creep into issuance
// derivation.

test("issuance tripwire: issued_at still derives from intent.timestamp, not evaluationTime", () => {
  const engine = makeEngine();
  // evaluationTime deliberately differs from intent.timestamp (both fresh,
  // within tolerance) so this test would fail loudly if issuance were ever
  // switched to key off evaluationTime instead.
  const intent = makeIntent({ timestamp: T0 + 10 });
  const out = engine.evaluatePure(intent, freshState(), T0);
  assert.equal(out.decision, "ALLOW");
  if (out.decision !== "ALLOW") return;
  assert.equal(out.authorization.issued_at, intent.timestamp);
  assert.notEqual(out.authorization.issued_at, T0);
});
