// SPDX-License-Identifier: Apache-2.0
// packages/core/src/test/toctou.test.ts
//
// TOCTOU, state-binding, and enforcement-boundary tests.
//
// Scenarios:
//   T-1  state_snapshot_hash tamper → HMAC fails → AUTH_SIGNATURE_INVALID
//   T-2  policy_version mismatch    → POLICY_VERSION_MISMATCH
//   T-3  explicit now > expiry      → AUTH_EXPIRED
//   T-4  intent field mutation      → AUTH_INTENT_MISMATCH
//   T-5  auth_id in consumedAuthIds → AUTH_REPLAY  (standalone verifyAuthorization)
//   T-6  authorization_id double-RELEASE → CONCURRENCY_RELEASE_INVALID
//   T-7  mismatched engine secret   → AUTH_SIGNATURE_INVALID (cross-engine artifact)
//   T-8  expired parent delegation  → DELEGATION_PARENT_EXPIRED (chain level)
//   T-9  delegation scope escape    → DELEGATION_SCOPE_VIOLATION (amount)
//   T-10 delegation scope escape    → guard blocks tool not in scope
//   T-11 clean RELEASE removes its own lease, preserves unrelated leases
//   T-12 expired lease reclaimed during EXECUTE
//   T-13 exact expires_at boundary is expired
//   T-14 saturation recovery after abandoned leases
//   T-15 late RELEASE after reclaim → CONCURRENCY_RELEASE_INVALID
//   T-16 malformed expires_at fails closed → STATE_INVALID
//   T-17 reclamation removes only eligible entries
//   T-18 two evaluators on one version cannot double-decrement
//   T-19 EXECUTE fails closed when active under-counts tracked leases
//   T-20 RELEASE shares that under-count precondition

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import { signAuthorizationEd25519, verifyAuthorization } from "../verification/verifyAuthorization.js";
import { createDelegation } from "../delegation/createDelegation.js";
import { verifyDelegation, verifyDelegationChain } from "../verification/verifyDelegation.js";
import type { State } from "../types/state.js";
import type { Intent } from "../types/intent.js";
import type { Authorization } from "../types/authorization.js";
import type { KeySet } from "../types/keyset.js";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const POLICY = "v-toctou";
const T0 = 1_700_000_000; // base timestamp
const TTL = 60;

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: POLICY,
    engine_secret: "toctou-test-secret-32-bytes-ok!!",
    authorization_ttl_seconds: TTL,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeState(): State {
  return {
    policy_version: POLICY,
    period_id: "toctou-period",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit:    { "agent-1": 1_000_000n },
      spent_in_period: { "agent-1": 0n },
    },
    max_amount_per_action: { "agent-1": 500_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 100 }, counters: {} },
    replay:   { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: {
      max_concurrent: { "agent-1": 3 },
      active: {},
      active_auths: {},
    },
    recursion: { max_depth: { "agent-1": 5 } },
    tool_limits: {
      window_seconds: 3600,
      max_calls: { "agent-1": 100 },
      calls: {},
    },
  };
}

function makeIntent(overrides: Partial<Intent> = {}): Intent {
  return {
    intent_id:     "toctou-intent-1",
    agent_id:      "agent-1",
    action_type:   "PAYMENT",
    amount:        1_000n,
    target:        "vendor-x",
    timestamp:     T0,
    metadata_hash: "0".repeat(64),
    nonce:         42n,
    signature:     "",
    depth:         0,
    type:          "EXECUTE",
    ...overrides,
  } as Intent;
}

// Issue a valid authorization and return it along with the next state.
function issueAuth(engine: PolicyEngine, state: State, intent: Intent) {
  const out = engine.evaluatePure(intent, state, T0);
  assert.equal(out.decision, "ALLOW", "fixture precondition: intent must ALLOW");
  return { authorization: out.authorization, nextState: out.nextState };
}

// ── T-1: state_snapshot_hash tamper → AUTH_SIGNATURE_INVALID ─────────────────

test("T-1 state_snapshot_hash tamper → AUTH_SIGNATURE_INVALID", () => {
  const engine = makeEngine();
  const state  = makeState();
  const intent = makeIntent({ nonce: 1n });

  const { authorization } = issueAuth(engine, state, intent);

  // Mutate the embedded state snapshot hash — the HMAC must no longer verify.
  // Cast as Authorization: runtime object has all legacy fields even though the
  // TypeScript type was narrowed to AuthorizationV1 at the evaluatePure boundary.
  const tampered = { ...authorization, state_snapshot_hash: "f".repeat(64) } as Authorization;

  const result = engine.verifyAuthorization(intent, tampered, state, T0);
  assert.equal(result.valid, false, "tampered state_snapshot_hash must fail verification");
  assert.equal(result.reason, "AUTH_SIGNATURE_INVALID",
    `expected AUTH_SIGNATURE_INVALID, got ${result.reason}`);
});

// ── T-2: policy_version mismatch → POLICY_VERSION_MISMATCH ───────────────────

test("T-2 policy_version mismatch → POLICY_VERSION_MISMATCH", () => {
  const engine = makeEngine();
  const state  = makeState();
  const intent = makeIntent({ nonce: 2n });

  const { authorization } = issueAuth(engine, state, intent);

  // Present the auth against a state whose policy_version is different.
  const altState: State = { ...state, policy_version: "v-other" };

  const result = engine.verifyAuthorization(intent, authorization as Authorization, altState, T0);
  assert.equal(result.valid, false, "policy_version mismatch must fail verification");
  assert.equal(result.reason, "POLICY_VERSION_MISMATCH",
    `expected POLICY_VERSION_MISMATCH, got ${result.reason}`);
});

// ── T-3: explicit now past expiry → AUTH_EXPIRED ──────────────────────────────

test("T-3 explicit now past expiry → AUTH_EXPIRED", () => {
  const engine = makeEngine(); // TTL = 60 s
  const state  = makeState();
  const intent = makeIntent({ nonce: 3n, timestamp: T0 });

  const { authorization } = issueAuth(engine, state, intent);
  // authorization.expiry = T0 + 60

  // Verify one second after expiry.
  const result = engine.verifyAuthorization(intent, authorization as Authorization, state, T0 + TTL + 1);
  assert.equal(result.valid, false, "expired authorization must be rejected");
  assert.equal(result.reason, "AUTH_EXPIRED",
    `expected AUTH_EXPIRED, got ${result.reason}`);
});

// ── T-4: intent field mutation → AUTH_INTENT_MISMATCH ────────────────────────

test("T-4 intent field mutation → AUTH_INTENT_MISMATCH", () => {
  const engine = makeEngine();
  const state  = makeState();
  const intent = makeIntent({ nonce: 4n, amount: 100n });

  const { authorization } = issueAuth(engine, state, intent);

  // Alter a binding field — a different amount changes the intent hash.
  const mutated = { ...intent, amount: 999n };

  const result = engine.verifyAuthorization(mutated, authorization as Authorization, state, T0);
  assert.equal(result.valid, false, "mutated intent must not verify against issued auth");
  assert.equal(result.reason, "AUTH_INTENT_MISMATCH",
    `expected AUTH_INTENT_MISMATCH, got ${result.reason}`);
});

// ── T-5: consumedAuthIds → AUTH_REPLAY (standalone verifyAuthorization) ───────

test("T-5 consumedAuthIds → AUTH_REPLAY blocks replay of consumed auth_id", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding:  { format: "pem", type: "spki"  },
  });

  const keyset: KeySet = {
    issuer: "issuer-toctou",
    version: "1",
    keys: [{ kid: "k1", alg: "Ed25519", public_key: publicKey }],
  };

  const auth = signAuthorizationEd25519(
    {
      auth_id:     "a".repeat(64),
      issuer:      "issuer-toctou",
      audience:    "agent-1",
      intent_hash: "b".repeat(64),
      state_hash:  "c".repeat(64),
      policy_id:   "d".repeat(64),
      decision:    "ALLOW",
      issued_at:   T0,
      expiry:      T0 + 300,
      kid:         "k1",
    },
    privateKey
  );

  // First check without consuming: ok.
  const first = verifyAuthorization(auth, {
    now: T0 + 10,
    trustedKeySets: keyset,
    requireSignatureVerification: true,
  });
  assert.equal(first.status, "ok", "first verification must succeed");

  // Second check with auth_id in consumedAuthIds: AUTH_REPLAY.
  const second = verifyAuthorization(auth, {
    now: T0 + 10,
    trustedKeySets: keyset,
    requireSignatureVerification: true,
    consumedAuthIds: [auth.auth_id],
  });
  assert.equal(second.status, "invalid");
  assert.ok(
    second.violations.some((v) => v.code === "AUTH_REPLAY"),
    `expected AUTH_REPLAY violation, got: ${JSON.stringify(second.violations)}`
  );
});

// ── T-6: RELEASE with unknown authorization_id → CONCURRENCY_RELEASE_INVALID ──

test("T-6 RELEASE with unknown authorization_id → CONCURRENCY_RELEASE_INVALID", () => {
  // Tests the fail-closed path for fabricated or already-expired authorization
  // IDs presented to the RELEASE lifecycle.
  //
  // The observation that previously sat here — deepMerge is additive, so the
  // RELEASE path could not remove the authorization_id from active_auths and
  // the stale entry persisted — was fixed in #227. PolicyEngine now assigns the
  // resulting lease map rather than merging it, so a successful RELEASE removes
  // its own entry and a second RELEASE of the same authorization_id is DENIED by
  // ConcurrencyModule on its own merits rather than only by nonce reuse in the
  // ReplayModule. T-11 asserts that removal directly.
  const engine = makeEngine();
  const state  = makeState();

  // Step 1: EXECUTE → ALLOW → record the auth_id and advance state.
  const execIntent = makeIntent({ nonce: 6n, type: "EXECUTE" });
  const execOut    = engine.evaluatePure(execIntent, state, T0);
  assert.equal(execOut.decision, "ALLOW", "EXECUTE precondition: must ALLOW");
  const authorization_id = execOut.authorization.auth_id;
  const stateAfterExec = execOut.nextState;

  // The slot is recorded in active_auths.
  assert.ok(
    stateAfterExec.concurrency.active_auths["agent-1"]?.[authorization_id],
    "authorization_id must appear in active_auths after EXECUTE"
  );

  // Step 2: RELEASE with valid authorization_id → ALLOW.
  // The active counter is decremented (from 1 to 0).
  const releaseIntent: Intent = {
    ...makeIntent({ nonce: 7n }),
    type:             "RELEASE",
    authorization_id: authorization_id,
  };
  const rel1 = engine.evaluatePure(releaseIntent, stateAfterExec, T0);
  assert.equal(rel1.decision, "ALLOW", "first RELEASE must ALLOW");
  const stateAfterRel1 = rel1.nextState;

  // The active counter must be decremented.
  assert.equal(
    stateAfterRel1.concurrency.active["agent-1"],
    0,
    "active counter must be 0 after RELEASE"
  );

  // Step 3: RELEASE with a fabricated / unknown authorization_id → DENY.
  const fakeRelease: Intent = {
    ...makeIntent({ nonce: 8n }),
    type:             "RELEASE",
    authorization_id: "f".repeat(64),  // not in active_auths
  };
  const rel2 = engine.evaluatePure(fakeRelease, stateAfterRel1, T0);
  assert.equal(rel2.decision, "DENY",
    "RELEASE with unknown authorization_id must DENY");
  assert.ok(
    rel2.reasons.includes("CONCURRENCY_RELEASE_INVALID"),
    `expected CONCURRENCY_RELEASE_INVALID, got: ${JSON.stringify(rel2.reasons)}`
  );
});

// ── T-7: mismatched engine secret → AUTH_SIGNATURE_INVALID ───────────────────

test("T-7 cross-engine artifact: wrong engine secret → AUTH_SIGNATURE_INVALID", () => {
  const engineA = new PolicyEngine({
    policy_version: POLICY,
    engine_secret: "secret-A-32-bytes-exactly-here!!",
    authorization_ttl_seconds: TTL,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
  const engineB = new PolicyEngine({
    policy_version: POLICY,
    engine_secret: "secret-B-32-bytes-exactly-here!!",
    authorization_ttl_seconds: TTL,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });

  const state  = makeState();
  const intent = makeIntent({ nonce: 7n });

  // Auth issued by engine A.
  const out = engineA.evaluatePure(intent, state, T0);
  assert.equal(out.decision, "ALLOW", "engine A precondition");

  // Verified by engine B (different secret) → HMAC mismatch.
  const result = engineB.verifyAuthorization(intent, out.authorization as Authorization, state, T0);
  assert.equal(result.valid, false,
    "auth issued by engine A must not verify against engine B");
  assert.equal(result.reason, "AUTH_SIGNATURE_INVALID",
    `expected AUTH_SIGNATURE_INVALID, got ${result.reason}`);
});

// ── T-8: expired parent delegation → DELEGATION_PARENT_EXPIRED ───────────────

test("T-8 delegation: expired parent authorization → DELEGATION_PARENT_EXPIRED", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding:  { format: "pem", type: "spki"  },
  });

  const parent = signAuthorizationEd25519(
    {
      auth_id:     "e".repeat(64),
      issuer:      "pdp",
      audience:    "agent-parent",
      intent_hash: "f".repeat(64),
      state_hash:  "0".repeat(64),
      policy_id:   "1".repeat(64),
      decision:    "ALLOW",
      issued_at:   T0,
      expiry:      T0 + 30,  // expires at T0+30
      kid:         "k1",
    },
    privateKey
  );

  const delegation = createDelegation(
    parent,
    {
      delegatee:    "agent-child",
      scope:        { tools: ["gpu_provision"] },
      expiry:       T0 + 30,
      kid:          "k1",
      delegationId: "del-toctou-t8",
      issuedAt:     T0,
    },
    privateKey
  );

  // Verify after parent has expired.
  const result = verifyDelegationChain(delegation, parent, { now: T0 + 31 });
  assert.equal(result.ok, false, "expired parent must cause chain rejection");
  assert.ok(
    result.violations.some((v) => v.code === "DELEGATION_PARENT_EXPIRED"),
    `expected DELEGATION_PARENT_EXPIRED, got: ${JSON.stringify(result.violations)}`
  );
});

// ── T-9: delegation scope escape (amount) → DELEGATION_SCOPE_VIOLATION ────────

test("T-9 delegation scope escape: amount exceeds max_amount → DELEGATION_SCOPE_VIOLATION", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding:  { format: "pem", type: "spki"  },
  });

  const parent = signAuthorizationEd25519(
    {
      auth_id:     "2".repeat(64),
      issuer:      "pdp",
      audience:    "agent-parent",
      intent_hash: "3".repeat(64),
      state_hash:  "4".repeat(64),
      policy_id:   "5".repeat(64),
      decision:    "ALLOW",
      issued_at:   T0,
      expiry:      T0 + 3600,
      kid:         "k1",
    },
    privateKey
  );

  // Delegation caps amount at 100.
  const delegation = createDelegation(
    parent,
    {
      delegatee:    "agent-child",
      scope:        { max_amount: 100n },
      expiry:       T0 + 1800,
      kid:          "k1",
      delegationId: "del-toctou-t9",
      issuedAt:     T0,
    },
    privateKey
  );

  // Verify delegation with a parent scope that allows 200 — but delegation
  // already constrains max_amount to 100, and the child requests 150.
  // parentScope of 200 passes the narrowing check (100 <= 200), so
  // DELEGATION_SCOPE_VIOLATION is not raised at the chain level here.
  // The meaningful scope enforcement happens at the PEP (guard) level.

  // Instead verify that scope.max_amount = 100n IS enforced by verifyDelegation
  // when a parentScope of 80n is provided (child asks for 100, parent only allows 80).
  const keyset: KeySet = {
    issuer: "agent-parent",
    version: "1",
    keys: [{ kid: "k1", alg: "Ed25519", public_key: publicKey }],
  };

  const result = verifyDelegation(delegation, {
    now: T0 + 10,
    parentScope: { max_amount: 80n }, // parent only allows up to 80
  });
  assert.equal(result.ok, false, "scope violation must be rejected");
  assert.ok(
    result.violations.some((v) => v.code === "DELEGATION_SCOPE_VIOLATION"),
    `expected DELEGATION_SCOPE_VIOLATION, got: ${JSON.stringify(result.violations)}`
  );
});

// ── T-10: delegation scope escape (tool) at chain level ───────────────────────

test("T-10 delegation scope escape: tool not in parentScope → DELEGATION_SCOPE_VIOLATION", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding:  { format: "pem", type: "spki"  },
  });

  const parent = signAuthorizationEd25519(
    {
      auth_id:     "6".repeat(64),
      issuer:      "pdp",
      audience:    "agent-parent",
      intent_hash: "7".repeat(64),
      state_hash:  "8".repeat(64),
      policy_id:   "9".repeat(64),
      decision:    "ALLOW",
      issued_at:   T0,
      expiry:      T0 + 3600,
      kid:         "k1",
    },
    privateKey
  );

  // Delegation grants tool "query_db".
  const delegation = createDelegation(
    parent,
    {
      delegatee:    "agent-child",
      scope:        { tools: ["query_db"] },
      expiry:       T0 + 1800,
      kid:          "k1",
      delegationId: "del-toctou-t10",
      issuedAt:     T0,
    },
    privateKey
  );

  // parentScope only allows "query_db" — child is requesting "provision_gpu"
  // which is NOT in the parent scope either; this is a scope-widening attempt.
  const result = verifyDelegation(delegation, {
    now: T0 + 10,
    parentScope: { tools: ["query_db"] },  // parent allows only query_db
  });
  // delegation.scope.tools = ["query_db"] ⊆ parentScope.tools = ["query_db"] → ok
  assert.equal(result.ok, true,
    "delegation whose scope.tools is a subset of parentScope.tools must be valid");

  // Now test a delegation that tries to claim a tool NOT in the parent scope.
  const escapeDelegation = createDelegation(
    parent,
    {
      delegatee:    "agent-child",
      scope:        { tools: ["provision_gpu"] },  // NOT in parentScope
      expiry:       T0 + 1800,
      kid:          "k1",
      delegationId: "del-toctou-t10-escape",
      issuedAt:     T0,
    },
    privateKey
  );

  const escapeResult = verifyDelegation(escapeDelegation, {
    now: T0 + 10,
    parentScope: { tools: ["query_db"] },  // parent only allows query_db
  });
  assert.equal(escapeResult.ok, false, "scope escape must be rejected");
  assert.ok(
    escapeResult.violations.some((v) => v.code === "DELEGATION_SCOPE_VIOLATION"),
    `expected DELEGATION_SCOPE_VIOLATION, got: ${JSON.stringify(escapeResult.violations)}`
  );
});

// ── #227 concurrency lease lifecycle ─────────────────────────────────────────
//
// T-11 clean RELEASE removes its own lease, preserves unrelated leases
// T-12 expired lease reclaimed during EXECUTE
// T-13 exact expires_at boundary is expired (evaluationTime >= expires_at)
// T-14 saturation recovery after abandoned leases
// T-15 late RELEASE after reclaim → CONCURRENCY_RELEASE_INVALID
// T-16 malformed expires_at fails closed → STATE_INVALID
// T-17 reclamation removes only eligible entries
// T-18 two evaluators reading one version cannot double-decrement
// T-19 EXECUTE fails closed when active under-counts tracked leases
// T-20 RELEASE shares that under-count precondition

const AUTH_A = "a".repeat(64);
const AUTH_B = "b".repeat(64);
const AUTH_C = "c".repeat(64);

// A state whose agent already holds leases, so reclamation has something to act
// on. `active` is seeded to the lease count, which is the consistent starting
// point a live deployment would be in.
function stateWithLeases(
  leases: Record<string, { expires_at: number }>,
  maxConcurrent = 3,
  active = Object.keys(leases).length
): State {
  const s = makeState();
  s.concurrency = {
    max_concurrent: { "agent-1": maxConcurrent },
    active: { "agent-1": active },
    active_auths: { "agent-1": leases },
  };
  return s;
}

function leaseKeys(s: State): string[] {
  return Object.keys(s.concurrency.active_auths["agent-1"] ?? {}).sort();
}

test("T-11 clean RELEASE removes its own active_auths entry and preserves unrelated leases", () => {
  const engine = makeEngine();
  const state = stateWithLeases({
    [AUTH_A]: { expires_at: T0 + 100 },
    [AUTH_B]: { expires_at: T0 + 100 },
  });

  const out = engine.evaluatePure(
    { ...makeIntent({ nonce: 111n }), type: "RELEASE", authorization_id: AUTH_A },
    state,
    T0
  );
  assert.equal(out.decision, "ALLOW", "RELEASE of a live lease must ALLOW");

  assert.deepEqual(
    leaseKeys(out.nextState),
    [AUTH_B],
    "RELEASE must remove exactly its own lease and leave unrelated leases resident"
  );
  assert.equal(
    out.nextState.concurrency.active["agent-1"],
    1,
    "active must be decremented by exactly the one entry removed"
  );
});

test("T-12 expired lease is reclaimed during EXECUTE", () => {
  const engine = makeEngine();
  const state = stateWithLeases({ [AUTH_A]: { expires_at: T0 - 1 } }, 3, 1);

  const out = engine.evaluatePure(makeIntent({ nonce: 112n }), state, T0);
  assert.equal(out.decision, "ALLOW");

  const keys = leaseKeys(out.nextState);
  assert.ok(!keys.includes(AUTH_A), "expired lease must not remain resident");
  assert.equal(keys.length, 1, "only the newly issued lease remains");
  assert.equal(
    out.nextState.concurrency.active["agent-1"],
    1,
    "one reclaimed (-1) plus one issued (+1) leaves active at 1"
  );
});

test("T-13 a lease at exactly expires_at is expired and reclaimable", () => {
  const engine = makeEngine();

  // evaluationTime === expires_at → expired (strict zero-tolerance boundary).
  const atBoundary = engine.evaluatePure(
    makeIntent({ nonce: 113n }),
    stateWithLeases({ [AUTH_A]: { expires_at: T0 } }, 3, 1),
    T0
  );
  assert.equal(atBoundary.decision, "ALLOW");
  assert.ok(
    !leaseKeys(atBoundary.nextState).includes(AUTH_A),
    "at expires_at the lease is no longer live and must be reclaimed"
  );

  // One second earlier the same lease is still live and must be retained.
  const beforeBoundary = engine.evaluatePure(
    makeIntent({ nonce: 114n }),
    stateWithLeases({ [AUTH_A]: { expires_at: T0 } }, 3, 1),
    T0 - 1
  );
  assert.equal(beforeBoundary.decision, "ALLOW");
  assert.ok(
    leaseKeys(beforeBoundary.nextState).includes(AUTH_A),
    "one second before expires_at the lease is still live and must be retained"
  );
});

test("T-14 saturation recovers after every lease is abandoned", () => {
  const engine = makeEngine();
  // Both slots held by leases whose holder never sent a RELEASE.
  const state = stateWithLeases(
    { [AUTH_A]: { expires_at: T0 - 5 }, [AUTH_B]: { expires_at: T0 - 5 } },
    2,
    2
  );

  // Before expiry the agent is genuinely saturated.
  const saturated = engine.evaluatePure(makeIntent({ nonce: 115n }), state, T0 - 10);
  assert.equal(saturated.decision, "DENY", "live leases must still consume capacity");
  assert.deepEqual(saturated.reasons, ["CONCURRENCY_LIMIT_EXCEEDED"]);

  // Once expired, capacity returns without any operator intervention.
  const recovered = engine.evaluatePure(makeIntent({ nonce: 116n }), state, T0);
  assert.equal(recovered.decision, "ALLOW", "expired leases must stop consuming capacity");
  assert.equal(leaseKeys(recovered.nextState).length, 1, "both abandoned leases reclaimed");
  assert.equal(recovered.nextState.concurrency.active["agent-1"], 1);
});

test("T-15 RELEASE arriving after its lease was reclaimed → CONCURRENCY_RELEASE_INVALID", () => {
  const engine = makeEngine();
  const state = stateWithLeases({ [AUTH_A]: { expires_at: T0 - 1 } }, 3, 1);

  const out = engine.evaluatePure(
    { ...makeIntent({ nonce: 117n }), type: "RELEASE", authorization_id: AUTH_A },
    state,
    T0
  );
  assert.equal(out.decision, "DENY", "a late RELEASE must not be silently idempotent");
  assert.deepEqual(out.reasons, ["CONCURRENCY_RELEASE_INVALID"]);
});

test("T-16 malformed expires_at fails closed with STATE_INVALID", () => {
  const engine = makeEngine();

  const malformed: ReadonlyArray<readonly [string, number]> = [
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["non-integer", T0 + 0.5],
    ["negative", -1],
  ];

  for (const [label, bad] of malformed) {
    const state = stateWithLeases({ [AUTH_A]: { expires_at: bad } }, 3, 1);

    const exec = engine.evaluatePure(makeIntent({ nonce: 118n }), state, T0);
    assert.equal(exec.decision, "DENY", `EXECUTE must fail closed on ${label} expires_at`);
    assert.deepEqual(exec.reasons, ["STATE_INVALID"], `EXECUTE reason for ${label}`);

    const rel = engine.evaluatePure(
      { ...makeIntent({ nonce: 119n }), type: "RELEASE", authorization_id: AUTH_A },
      state,
      T0
    );
    assert.equal(rel.decision, "DENY", `RELEASE must fail closed on ${label} expires_at`);
    assert.deepEqual(rel.reasons, ["STATE_INVALID"], `RELEASE reason for ${label}`);
  }
});

test("T-17 reclamation removes only eligible entries", () => {
  const engine = makeEngine();
  const state = stateWithLeases(
    {
      [AUTH_A]: { expires_at: T0 - 10 }, // expired  → reclaim
      [AUTH_B]: { expires_at: T0 },      // boundary → reclaim
      [AUTH_C]: { expires_at: T0 + 10 }, // live     → keep
    },
    3,
    3
  );

  const out = engine.evaluatePure(makeIntent({ nonce: 120n }), state, T0);
  assert.equal(out.decision, "ALLOW");

  const keys = leaseKeys(out.nextState);
  assert.ok(keys.includes(AUTH_C), "a live lease must survive reclamation");
  assert.ok(!keys.includes(AUTH_A) && !keys.includes(AUTH_B), "only expired leases are removed");
  assert.equal(keys.length, 2, "the live lease plus the newly issued one");

  // active is decremented by exactly the number removed (3 - 2), then the new
  // lease adds one back — which is also the resulting map size.
  assert.equal(out.nextState.concurrency.active["agent-1"], 2);
  assert.equal(
    out.nextState.concurrency.active["agent-1"],
    keys.length,
    "scalar active must agree with the resulting lease map"
  );
});

test("T-18 two evaluators reading the same version cannot double-decrement", () => {
  // Core's StateStore is a plain get/set; the exact-version CAS that serializes
  // committers lives in the Profile C StateProvider. What is asserted here is
  // the property that makes that CAS sufficient: reclamation is a pure function
  // of (intent, state, evaluationTime), so two evaluators racing from the same
  // version compute the *same* transition rather than two stacking ones.
  // Whichever wins the CAS commits exactly one decrement; the loser is rejected
  // and re-evaluates against the winner's state.
  const engine = makeEngine();
  const base = stateWithLeases(
    { [AUTH_A]: { expires_at: T0 - 1 }, [AUTH_B]: { expires_at: T0 + 100 } },
    3,
    2
  );

  const releaseB = { ...makeIntent({ nonce: 121n }), type: "RELEASE", authorization_id: AUTH_B } as Intent;
  const first = engine.evaluatePure(releaseB, base, T0);
  const second = engine.evaluatePure(releaseB, base, T0);
  assert.equal(first.decision, "ALLOW");
  assert.equal(second.decision, "ALLOW");

  // AUTH_A reclaimed (-1) and AUTH_B released (-1): exactly two removals, once.
  assert.equal(first.nextState.concurrency.active["agent-1"], 0);
  assert.equal(
    second.nextState.concurrency.active["agent-1"],
    first.nextState.concurrency.active["agent-1"],
    "the same version must yield the same counter, never a stacked decrement"
  );
  assert.deepEqual(leaseKeys(first.nextState), []);
  assert.deepEqual(leaseKeys(second.nextState), leaseKeys(first.nextState));

  // Re-evaluating the loser against the winner's committed state is the DENY
  // that prevents the second decrement from ever being applied.
  const loserRetry = engine.evaluatePure(
    { ...makeIntent({ nonce: 122n }), type: "RELEASE", authorization_id: AUTH_B },
    first.nextState,
    T0
  );
  assert.equal(loserRetry.decision, "DENY");
  assert.deepEqual(loserRetry.reasons, ["CONCURRENCY_RELEASE_INVALID"]);
});

test("T-19 EXECUTE fails closed when active under-counts tracked leases", () => {
  const engine = makeEngine();

  // AngeYobo's case on #231: max_concurrent 1, active 0, one live tracked
  // lease. Without the precondition an EXECUTE reads zero usage, ALLOWs, and
  // leaves two live leases against a limit of one.
  const underCounted = stateWithLeases({ [AUTH_A]: { expires_at: T0 + 100 } }, 1, 0);

  const denied = engine.evaluatePure(makeIntent({ nonce: 120n }), underCounted, T0);
  assert.equal(denied.decision, "DENY", "active < tracked leases must fail closed");
  assert.deepEqual(denied.reasons, ["STATE_INVALID"], "under-count is invalid state, not a limit breach");

  // Under-count is rejected even with headroom on max_concurrent, because the
  // defect is in the authoritative state, not in the limit.
  const roomySpare = stateWithLeases(
    { [AUTH_A]: { expires_at: T0 + 100 }, [AUTH_B]: { expires_at: T0 + 100 } },
    9,
    1
  );
  const deniedRoomy = engine.evaluatePure(makeIntent({ nonce: 121n }), roomySpare, T0);
  assert.equal(deniedRoomy.decision, "DENY", "under-count is invalid regardless of spare capacity");
  assert.deepEqual(deniedRoomy.reasons, ["STATE_INVALID"]);

  // Equality is NOT required. active > tracked stays valid and conservative:
  // a deployment may account capacity it never lease-tracked, and that capacity
  // must keep being counted rather than being normalized away.
  const overCounted = stateWithLeases({ [AUTH_A]: { expires_at: T0 + 100 } }, 3, 2);
  const allowed = engine.evaluatePure(makeIntent({ nonce: 122n }), overCounted, T0);
  assert.equal(allowed.decision, "ALLOW", "active > tracked leases must remain valid");
  assert.equal(
    allowed.nextState.concurrency.active["agent-1"],
    3,
    "untracked capacity is preserved: nothing reclaimed, one issued"
  );
});

test("T-20 RELEASE shares the under-count precondition and fails closed on it", () => {
  const engine = makeEngine();

  // Two live tracked leases, active seeded at 1. The RELEASE names a lease that
  // really is resident, so the only defect is the counter.
  const state = stateWithLeases(
    { [AUTH_A]: { expires_at: T0 + 100 }, [AUTH_B]: { expires_at: T0 + 100 } },
    3,
    1
  );

  const out = engine.evaluatePure(
    { ...makeIntent({ nonce: 123n }), type: "RELEASE", authorization_id: AUTH_A },
    state,
    T0
  );
  assert.equal(out.decision, "DENY", "RELEASE must fail closed on under-counted state");
  assert.deepEqual(
    out.reasons,
    ["STATE_INVALID"],
    "the state precondition precedes CONCURRENCY_RELEASE_INVALID: the lease is resident, the counter is wrong"
  );
});
