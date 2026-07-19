// SPDX-License-Identifier: Apache-2.0
// packages/core/src/test/verify.sufficiency.test.ts
//
// Snapshot + envelope SUFFICIENCY tests.
//
// Audits that the CanonicalState + VerificationEnvelopeV1 artifact set provides
// enough context for meaningful replay and stateless verification without
// hidden runtime state.
//
// Scenarios:
//   S-1  Codec round-trip is lossless: module payloads survive encode→decode
//   S-2  Hash contract: verifySnapshot.stateHash === engine.computeStateHash
//   S-3  Functional replay: importState restores nonce history,
//        blocking replay decisions in a fresh engine
//   S-4  State-binding: correctly-constructed envelope returns stateHash that
//        matches the STATE_CHECKPOINT built from engine.computeStateHash
//   S-5  State-binding gap: verifyEnvelope does NOT auto cross-check
//        snapshot.stateHash against STATE_CHECKPOINT.stateHash (documented)

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import { encodeCanonicalState, decodeCanonicalState } from "../snapshot/CanonicalCodec.js";
import { verifySnapshot } from "../verification/verifySnapshot.js";
import { encodeEnvelope } from "../verification/envelope.js";
import { verifyEnvelope } from "../verification/verifyEnvelope.js";
import type { AuditEntry } from "../audit/AuditLog.js";
import type { State } from "../types/state.js";
import type { Intent } from "../types/intent.js";
import type { KeySet } from "../types/keyset.js";

const _SUF_KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const SUF_KEYSET: KeySet = {
  issuer: "sufficiency-test-issuer",
  version: "1",
  keys: [{ kid: "suf-2026", alg: "Ed25519", public_key: _SUF_KEYPAIR.publicKey }]
};

// ── Fixtures ──────────────────────────────────────────────────────────────────

const POLICY_VERSION = "v0.9-suf";
const T0 = 1_700_000_000;
const AGENT = "agent-1";

function makeState(): State {
  return {
    policy_version: POLICY_VERSION,
    period_id: "period-suf",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit: { [AGENT]: 100_000n },
      spent_in_period: { [AGENT]: 0n }
    },
    max_amount_per_action: { [AGENT]: 50_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 1000 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { [AGENT]: 4 }, active: {}, active_auths: {} },
    recursion: { max_depth: { [AGENT]: 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { [AGENT]: 500 }, calls: {} }
  };
}

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: POLICY_VERSION,
    engine_secret: "sufficiency-test-secret-32-chars!",
    authorization_ttl_seconds: 300,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
}

function makeIntent(nonce: bigint): Intent {
  return {
    intent_id: `intent-suf-${nonce}`,
    agent_id: AGENT,
    action_type: "PAYMENT",
    target: "vendor-suf",
    metadata_hash: "0".repeat(64),
    signature: "",
    type: "EXECUTE",
    nonce,
    amount: 100n,
    timestamp: T0,
    depth: 0
  };
}

// ── S-1: encode/decode round-trip ─────────────────────────────────────────────

test("S-1 encode/decode round-trip is lossless: module payloads survive encode→decode", () => {
  const engine = makeEngine();
  const snapshot = engine.exportState(makeState());
  const bytes = encodeCanonicalState(snapshot);
  const decoded = decodeCanonicalState(bytes);

  assert.equal(decoded.formatVersion, 1);
  assert.equal(decoded.engineVersion, snapshot.engineVersion);
  assert.equal(decoded.policyId, snapshot.policyId);

  for (const id of Object.keys(snapshot.modules).sort()) {
    assert.deepEqual(
      decoded.modules[id],
      snapshot.modules[id],
      `module ${id}: decoded payload must match original`
    );
  }
});

// ── S-2: stateHash contract ───────────────────────────────────────────────────

test("S-2 stateHash contract: verifySnapshot.stateHash equals engine.computeStateHash", () => {
  // The stateHash computed by the stateless verifier must equal the hash
  // the engine uses in STATE_CHECKPOINT events and in authorization artifacts.
  // If this invariant holds, snapshot-based verification is cryptographically
  // equivalent to live engine verification.
  const engine = makeEngine();
  const state = makeState();
  const bytes = encodeCanonicalState(engine.exportState(state));

  const snapshotResult = verifySnapshot(bytes);
  assert.equal(snapshotResult.ok, true);

  const engineHash = engine.computeStateHash(state);

  assert.equal(
    snapshotResult.stateHash,
    engineHash,
    "verifySnapshot stateHash must equal engine.computeStateHash for the same state"
  );
});

// ── S-3: functional replay ────────────────────────────────────────────────────

test("S-3 functional replay: importState restores nonce history, blocking replay in fresh engine", () => {
  // Verifies that a canonical snapshot carries enough state for a fresh engine
  // instance to reject a previously-seen nonce — the core TOCTOU guarantee
  // across process/instance boundaries.
  const engine = makeEngine();
  const initial = makeState();
  const intent = makeIntent(777n);

  // First evaluation: ALLOW, state advances with nonce 777 recorded.
  const result1 = engine.evaluatePure(intent, initial, T0);
  assert.equal(result1.decision, "ALLOW", "first evaluation must be ALLOW");
  if (result1.decision !== "ALLOW") throw new Error("expected ALLOW");
  const advancedState = result1.nextState;

  // Export and encode the advanced state.
  const snapshot = engine.exportState(advancedState);
  const bytes = encodeCanonicalState(snapshot);

  // Decode and import into a fresh engine instance.
  const freshEngine = makeEngine();
  const target = makeState();
  freshEngine.importState(target, decodeCanonicalState(bytes));

  // Re-run the same intent against the imported state: must DENY as REPLAY.
  const result2 = freshEngine.evaluatePure(intent, target, T0);
  assert.equal(result2.decision, "DENY",
    "replayed nonce must be DENY after importState into fresh engine");
  assert.ok(
    result2.reasons.some((r) => r === "REPLAY_NONCE" || r === "REPLAY_DETECTED"),
    `expected REPLAY_NONCE or REPLAY_DETECTED reason, got: ${JSON.stringify(result2.reasons)}`
  );
});

// ── S-4: state-binding via correctly-constructed envelope ─────────────────────

test("S-4 state-binding: correctly-built envelope — verifyEnvelope.stateHash matches STATE_CHECKPOINT", () => {
  // Shows that when an integrator builds the envelope correctly (snapshot from
  // the same state as the STATE_CHECKPOINT, using engine.computeStateHash),
  // verifyEnvelope returns a stateHash equal to the checkpoint stateHash,
  // providing full state continuity verification.
  const engine = makeEngine();
  const initial = makeState();
  const policyId = engine.computePolicyId();

  const intent = makeIntent(888n);
  const result = engine.evaluatePure(intent, initial, T0);
  assert.equal(result.decision, "ALLOW");
  const nextState = result.nextState;

  // Export the post-decision state as snapshot.
  const snapshotBytes = encodeCanonicalState(engine.exportState(nextState));

  // Build audit events with the real stateHash from engine.computeStateHash.
  const realStateHash = engine.computeStateHash(nextState);
  const events: AuditEntry[] = [
    {
      type: "INTENT_RECEIVED",
      intent_hash: "ih-suf-1",
      agent_id: AGENT,
      timestamp: T0,
      policyId
    },
    {
      type: "DECISION",
      intent_hash: "ih-suf-1",
      decision: "ALLOW",
      reasons: [],
      policy_version: POLICY_VERSION,
      timestamp: T0 + 1,
      policyId
    },
    {
      type: "STATE_CHECKPOINT",
      stateHash: realStateHash,
      timestamp: T0 + 2,
      policyId
    }
  ];

  const envelopeBytes = encodeEnvelope({ formatVersion: 1, snapshot: snapshotBytes, events });
  const out = verifyEnvelope(envelopeBytes, { mode: "strict", trustedKeySets: SUF_KEYSET });

  assert.equal(out.ok, true);
  assert.equal(out.stateHash, realStateHash,
    "verifyEnvelope stateHash must equal STATE_CHECKPOINT stateHash when built correctly");
});

// ── S-5: state-binding gap (documented) ──────────────────────────────────────

test("S-5 state-binding gap: verifyEnvelope passes even when snapshot and STATE_CHECKPOINT describe different states", () => {
  // Demonstrates a known verifier limitation: verifyEnvelope does NOT
  // automatically cross-check snapshot.stateHash against STATE_CHECKPOINT.stateHash
  // in audit events.  Both hashes are returned independently in the result; the
  // consumer is responsible for comparing them when state continuity matters.
  //
  // Protocol assessment: SUFFICIENT — all information needed for state binding
  // is present in the envelope.  Verifier assessment: does not auto-enforce it.
  const engine = makeEngine();
  const policyId = engine.computePolicyId();
  const initial = makeState();

  // Two successive decisions → two distinct states.
  const r1 = engine.evaluatePure(makeIntent(901n), initial, T0);
  assert.equal(r1.decision, "ALLOW");
  if (r1.decision !== "ALLOW") throw new Error("expected ALLOW");
  const r2 = engine.evaluatePure(makeIntent(902n), r1.nextState, T0);
  assert.equal(r2.decision, "ALLOW");
  if (r2.decision !== "ALLOW") throw new Error("expected ALLOW");

  // Snapshot is taken from the EARLIER state (after r1 only).
  const snapshotBytes = encodeCanonicalState(engine.exportState(r1.nextState));
  const snapshotStateHash = engine.computeStateHash(r1.nextState);

  // Events describe the LATER state (after r1 + r2).
  const laterStateHash = engine.computeStateHash(r2.nextState);

  assert.notEqual(snapshotStateHash, laterStateHash,
    "test setup: snapshot and checkpoint states must differ");

  const events: AuditEntry[] = [
    {
      type: "INTENT_RECEIVED",
      intent_hash: "ih-suf-2",
      agent_id: AGENT,
      timestamp: T0,
      policyId
    },
    {
      type: "DECISION",
      intent_hash: "ih-suf-2",
      decision: "ALLOW",
      reasons: [],
      policy_version: POLICY_VERSION,
      timestamp: T0 + 1,
      policyId
    },
    {
      type: "STATE_CHECKPOINT",
      stateHash: laterStateHash,
      timestamp: T0 + 2,
      policyId
    }
  ];

  const envelopeBytes = encodeEnvelope({ formatVersion: 1, snapshot: snapshotBytes, events });
  const out = verifyEnvelope(envelopeBytes, { mode: "strict", trustedKeySets: SUF_KEYSET });

  // verifyEnvelope returns ok: true despite snapshot and checkpoint describing
  // different states — no automatic cross-check is performed.
  assert.equal(out.ok, true,
    "verifyEnvelope does not cross-check snapshot.stateHash against STATE_CHECKPOINT.stateHash");

  // The consumer CAN detect the mismatch by comparing result.stateHash
  // against the expected checkpoint stateHash.
  const checkpointEvent = events.find(e => e.type === "STATE_CHECKPOINT");
  assert.ok(checkpointEvent?.type === "STATE_CHECKPOINT");
  assert.notEqual(out.stateHash, checkpointEvent.stateHash,
    "consumer can detect mismatch: result.stateHash differs from STATE_CHECKPOINT.stateHash");
});
