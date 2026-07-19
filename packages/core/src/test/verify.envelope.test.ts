// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import { encodeCanonicalState } from "../snapshot/CanonicalCodec.js";
import { encodeEnvelope, signEnvelopeEd25519, verifyEnvelope } from "../verification/index.js";
import type { AuditEntry } from "../audit/AuditLog.js";
import type { State } from "../types/state.js";
import type { KeySet } from "../types/keyset.js";

const TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

function baseState(): State {
  return {
    policy_version: "v0.9-test",
    period_id: "period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit: { "agent-1": 10_000n },
      spent_in_period: { "agent-1": 0n }
    },
    max_amount_per_action: { "agent-1": 5_000n },
    velocity: {
      config: { window_seconds: 60, max_actions: 100 },
      counters: {}
    },
    replay: {
      window_seconds: 3600,
      max_nonces_per_agent: 256,
      nonces: {}
    },
    concurrency: {
      max_concurrent: { "agent-1": 2 },
      active: {},
      active_auths: {}
    },
    recursion: {
      max_depth: { "agent-1": 3 }
    },
    tool_limits: {
      window_seconds: 60,
      max_calls: { "agent-1": 10 },
      calls: {}
    }
  };
}

function makeSnapshotBytes() {
  const engine = new PolicyEngine({
    policy_version: "v0.9-test",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
  const snapshot = engine.exportState(baseState());
  return { policyId: engine.computePolicyId(), bytes: encodeCanonicalState(snapshot) };
}

function makeAuditEvents(policyId: string, withCheckpoint: boolean): AuditEntry[] {
  const events: AuditEntry[] = [
    {
      type: "INTENT_RECEIVED",
      intent_hash: "ih-1",
      agent_id: "agent-1",
      timestamp: 100,
      policyId
    },
    {
      type: "DECISION",
      intent_hash: "ih-1",
      decision: "ALLOW",
      reasons: [],
      policy_version: "v0.9-test",
      timestamp: 101,
      policyId
    }
  ];

  if (withCheckpoint) {
    events.push({
      type: "STATE_CHECKPOINT",
      stateHash: "a".repeat(64),
      timestamp: 102,
      policyId
    });
  }

  return events;
}

const TEST_KEYSET: KeySet = {
  issuer: "oxdeai.policy-engine",
  version: "1",
  keys: [{ kid: "2026-01", alg: "Ed25519", public_key: TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.publicKey }]
};

test("ok: valid snapshot + audit + checkpoint in strict mode", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: bytes,
    events: makeAuditEvents(policyId, true)
  });

  const out = verifyEnvelope(envelopeBytes, { mode: "strict", trustedKeySets: TEST_KEYSET });
  assert.equal(out.ok, true);
  assert.equal(out.status, "ok");
  assert.equal(out.policyId, policyId);
  assert.ok(typeof out.stateHash === "string" && out.stateHash.length === 64);
  assert.ok(typeof out.auditHeadHash === "string" && out.auditHeadHash.length === 64);
  assert.deepEqual(out.violations, []);
});

test("inconclusive: strict mode without STATE_CHECKPOINT", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: bytes,
    events: makeAuditEvents(policyId, false)
  });

  const out = verifyEnvelope(envelopeBytes, { mode: "strict", trustedKeySets: TEST_KEYSET });
  assert.equal(out.ok, false);
  assert.equal(out.status, "inconclusive");
  assert.ok(out.violations.some((v) => v.code === "NO_STATE_ANCHOR"));
});

test("invalid: snapshot policyId mismatch with audit policyId", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: bytes,
    events: makeAuditEvents(`${policyId}-other`, true)
  });

  const out = verifyEnvelope(envelopeBytes, { mode: "best-effort" });
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "POLICY_ID_MISMATCH"));
});

test("invalid: corrupt envelope bytes", () => {
  const out = verifyEnvelope(new Uint8Array([1, 2, 3]));
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "ENVELOPE_MALFORMED"));
});

test("invalid: malformed envelope schema", () => {
  const bad = {
    formatVersion: 1,
    snapshot: "not-base64",
    events: "bad"
  };
  const bytes = new TextEncoder().encode(JSON.stringify(bad));

  const out = verifyEnvelope(bytes);
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "ENVELOPE_MALFORMED"));
});

test("ok: signed envelope verifies with trusted keyset", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const signed = signEnvelopeEd25519(
    {
      formatVersion: 1,
      snapshot: bytes,
      events: makeAuditEvents(policyId, true)
    },
    { issuer: "oxdeai.policy-engine", kid: "2026-01", privateKeyPem: TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.privateKey }
  );
  const out = verifyEnvelope(encodeEnvelope(signed), {
    mode: "strict",
    expectedIssuer: "oxdeai.policy-engine",
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "ok");
});

test("invalid: strict mode without trustedKeySets fails closed with TRUSTED_KEYSETS_REQUIRED", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: bytes,
    events: makeAuditEvents(policyId, true)
  });

  const out = verifyEnvelope(envelopeBytes, { mode: "strict" });
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
});

test("invalid: strict mode with empty trustedKeySets array fails closed with TRUSTED_KEYSETS_REQUIRED", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: bytes,
    events: makeAuditEvents(policyId, true)
  });

  const out = verifyEnvelope(envelopeBytes, { mode: "strict", trustedKeySets: [] });
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
});

test("ok: strict mode with trustedKeySets does not fail the guard", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: bytes,
    events: makeAuditEvents(policyId, true)
  });

  const out = verifyEnvelope(envelopeBytes, { mode: "strict", trustedKeySets: TEST_KEYSET });
  assert.equal(out.ok, true);
  assert.equal(out.status, "ok");
  assert.equal(out.violations.filter((v) => v.code === "TRUSTED_KEYSETS_REQUIRED").length, 0);
});

test("invalid: signed envelope tampering fails signature verification", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const signed = signEnvelopeEd25519(
    {
      formatVersion: 1,
      snapshot: bytes,
      events: makeAuditEvents(policyId, true)
    },
    { issuer: "oxdeai.policy-engine", kid: "2026-01", privateKeyPem: TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.privateKey }
  );
  const tampered = { ...signed, events: [...signed.events, { ...signed.events[0] }] };
  const out = verifyEnvelope(encodeEnvelope(tampered), {
    mode: "strict",
    expectedIssuer: "oxdeai.policy-engine",
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "ENVELOPE_SIGNATURE_INVALID"));
});
