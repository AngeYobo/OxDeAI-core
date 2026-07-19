// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { createVerifier } from "../verification/createVerifier.js";
import { signAuthorizationEd25519 } from "../verification/verifyAuthorization.js";
import { encodeEnvelope, signEnvelopeEd25519 } from "../verification/envelope.js";
import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import { encodeCanonicalState } from "../snapshot/CanonicalCodec.js";
import type { KeySet } from "../types/keyset.js";
import type { State } from "../types/state.js";
import type { AuditEntry } from "../audit/AuditLog.js";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding:  { format: "pem", type: "spki" },
});

const TRUSTED_KEYSET: KeySet = {
  issuer: "trusted-issuer",
  version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: KP.publicKey }],
};

const OTHER_KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding:  { format: "pem", type: "spki" },
});

const OTHER_KEYSET: KeySet = {
  issuer: "other-issuer",
  version: "1",
  keys: [{ kid: "k2", alg: "Ed25519", public_key: OTHER_KP.publicKey }],
};

function makeAuth(issuer = "trusted-issuer", kid = "k1", privateKey = KP.privateKey) {
  return signAuthorizationEd25519(
    {
      auth_id:     "a".repeat(64),
      issuer,
      audience:    "rp-1",
      intent_hash: "b".repeat(64),
      state_hash:  "c".repeat(64),
      policy_id:   "d".repeat(64),
      decision:    "ALLOW",
      issued_at:   1_000,
      expiry:      2_000,
      kid,
    },
    privateKey
  );
}

function makeEngine() {
  return new PolicyEngine({
    policy_version: "v0.9-test",
    engine_secret: "create-verifier-test-secret-32ch!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeSnapshotBytes() {
  const engine = makeEngine();
  const state: State = {
    policy_version: "v0.9-test",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: { budget_limit: { "a1": 1000n }, spent_in_period: { "a1": 0n } },
    max_amount_per_action: { "a1": 500n },
    velocity: { config: { window_seconds: 60, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "a1": 2 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "a1": 3 } },
    tool_limits: { window_seconds: 60, max_calls: { "a1": 10 }, calls: {} },
  };
  return { policyId: engine.computePolicyId(), bytes: encodeCanonicalState(engine.exportState(state)) };
}

function makeEvents(policyId: string, withCheckpoint: boolean): AuditEntry[] {
  const events: AuditEntry[] = [
    { type: "INTENT_RECEIVED", intent_hash: "ih1", agent_id: "a1", timestamp: 100, policyId },
    { type: "DECISION", intent_hash: "ih1", decision: "ALLOW", reasons: [], policy_version: "v0.9-test", timestamp: 101, policyId },
  ];
  if (withCheckpoint) {
    events.push({ type: "STATE_CHECKPOINT", stateHash: "e".repeat(64), timestamp: 102, policyId });
  }
  return events;
}

// ── Construction guards ───────────────────────────────────────────────────────

test("createVerifier: throws when trustedKeySets is empty - trust boundary cannot be empty", () => {
  assert.throws(
    () => createVerifier({ trustedKeySets: [] }),
    /trustedKeySets must not be empty/
  );
});

test("createVerifier: returns bound verifier when trustedKeySets is non-empty", () => {
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET] });
  assert.equal(typeof v.verifyAuthorization, "function");
  assert.equal(typeof v.verifyEnvelope, "function");
});

// ── verifyAuthorization - trust enforcement ───────────────────────────────────

test("verifyAuthorization: ok - artifact from trusted issuer with valid signature", () => {
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET] });
  const out = v.verifyAuthorization(makeAuth(), { now: 1500 });
  assert.equal(out.ok, true);
  assert.equal(out.status, "ok");
  assert.deepEqual(out.violations, []);
});

test("verifyAuthorization: invalid - artifact signed by untrusted issuer is rejected", () => {
  // OTHER_KP is not in TRUSTED_KEYSET - only TRUSTED_KEYSET is configured
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET] });
  const auth = makeAuth("other-issuer", "k2", OTHER_KP.privateKey);
  const out = v.verifyAuthorization(auth, { now: 1500 });
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  // kid k2 is not in TRUSTED_KEYSET (which only has k1 for trusted-issuer)
  assert.ok(out.violations.some((v) => v.code === "AUTH_KID_UNKNOWN"));
});

test("verifyAuthorization: invalid - tampered artifact fails signature check", () => {
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET] });
  const auth = { ...makeAuth(), state_hash: "f".repeat(64) };
  const out = v.verifyAuthorization(auth, { now: 1500 });
  assert.equal(out.ok, false);
  assert.ok(out.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
});

test("verifyAuthorization: adding untrusted issuer to the verifier grants access - trust is explicit", () => {
  // Demonstrates that configuring a second keyset explicitly extends trust
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET, OTHER_KEYSET] });
  const auth = makeAuth("other-issuer", "k2", OTHER_KP.privateKey);
  const out = v.verifyAuthorization(auth, { now: 1500 });
  assert.equal(out.ok, true);
});

// ── expectedIssuer binding ────────────────────────────────────────────────────

test("verifyAuthorization: config-level expectedIssuer is applied automatically", () => {
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET], expectedIssuer: "trusted-issuer" });
  const out = v.verifyAuthorization(makeAuth(), { now: 1500 });
  assert.equal(out.ok, true);
});

test("verifyAuthorization: config-level expectedIssuer rejects wrong issuer", () => {
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET, OTHER_KEYSET], expectedIssuer: "trusted-issuer" });
  const auth = makeAuth("other-issuer", "k2", OTHER_KP.privateKey);
  const out = v.verifyAuthorization(auth, { now: 1500 });
  assert.equal(out.ok, false);
  assert.ok(out.violations.some((v) => v.code === "AUTH_ISSUER_MISMATCH"));
});

test("verifyAuthorization: per-call expectedIssuer overrides config-level", () => {
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET, OTHER_KEYSET], expectedIssuer: "trusted-issuer" });
  const auth = makeAuth("other-issuer", "k2", OTHER_KP.privateKey);
  const out = v.verifyAuthorization(auth, { now: 1500, expectedIssuer: "other-issuer" });
  assert.equal(out.ok, true);
});

// ── verifyEnvelope - trust enforcement ────────────────────────────────────────

test("verifyEnvelope: ok - signed envelope from trusted issuer with checkpoint", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const signed = signEnvelopeEd25519(
    { formatVersion: 1, snapshot: bytes, events: makeEvents(policyId, true) },
    { issuer: "trusted-issuer", kid: "k1", privateKeyPem: KP.privateKey }
  );
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET] });
  const out = v.verifyEnvelope(encodeEnvelope(signed));
  assert.equal(out.ok, true);
  assert.deepEqual(out.violations, []);
});

test("verifyEnvelope: inconclusive - envelope without STATE_CHECKPOINT (strict mode)", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const envelopeBytes = encodeEnvelope({
    formatVersion: 1, snapshot: bytes, events: makeEvents(policyId, false)
  });
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET] });
  const out = v.verifyEnvelope(envelopeBytes);
  assert.equal(out.ok, false);
  assert.equal(out.status, "inconclusive");
  assert.ok(out.violations.some((v) => v.code === "NO_STATE_ANCHOR"));
});

test("verifyEnvelope: invalid - envelope signed by untrusted issuer is rejected", () => {
  const { policyId, bytes } = makeSnapshotBytes();
  const signed = signEnvelopeEd25519(
    { formatVersion: 1, snapshot: bytes, events: makeEvents(policyId, true) },
    { issuer: "other-issuer", kid: "k2", privateKeyPem: OTHER_KP.privateKey }
  );
  const v = createVerifier({ trustedKeySets: [TRUSTED_KEYSET] });
  const out = v.verifyEnvelope(encodeEnvelope(signed));
  assert.equal(out.ok, false);
  assert.ok(out.violations.some((v) => v.code === "ENVELOPE_KID_UNKNOWN"));
});
