import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { PolicyEngine, signAuthorizationEd25519, verifyAuthorization } from "@oxdeai/core";
import type { Authorization, KeySet } from "@oxdeai/core";
import { makeIntent } from "../../helpers/intent.js";
import { makeState } from "../../helpers/state.js";

const TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    authorization_issuer: "issuer-A",
    authorization_audience: "rp-A",
    policyId: "a".repeat(64)
  });
}

const TEST_KEYSET: KeySet = {
  issuer: "issuer-A",
  version: "1",
  keys: [{ kid: "2026-01", alg: "Ed25519", public_key: TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.publicKey }]
};

function allowOutput() {
  const engine = makeEngine();
  const intent = makeIntent({
    nonce: 1n,
    amount: 1_000_000n,
    asset: "USDC",
    target: "t1",
    timestamp: 1000
  });
  const state = makeState({
    policy_version: "0.1.0",
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["t1"] },
    budget: { budget_limit: { "agent-1": 10_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 5_000_000n }
  });

  const out = engine.evaluatePure(intent, state);
  if (out.decision !== "ALLOW") {
    throw new Error(`expected ALLOW, got DENY: ${out.reasons.join(",")}`);
  }
  return { out, intent, state, engine };
}

test("creation emits AuthorizationV1 fields on ALLOW", () => {
  const { out, state, engine } = allowOutput();
  const auth = out.authorization;
  // Cast to Authorization to access internal engine fields in this compatibility test.
  // The runtime object still carries them; only the TypeScript type was narrowed.
  const authInternal = out.authorization as Authorization;

  assert.equal(auth.decision, "ALLOW");
  assert.ok(typeof auth.auth_id === "string" && auth.auth_id.length > 0);
  assert.equal(auth.auth_id, authInternal.authorization_id);
  assert.equal(auth.issuer, "issuer-A");
  assert.equal(auth.audience, "rp-A");
  // state_hash commits to the pre-evaluation input state (PEP boundary binding).
  // state_snapshot_hash commits to the post-evaluation state (engine_signature HMAC).
  // They must differ because evaluation changes the state (nonces, budget, etc.).
  assert.equal(auth.state_hash, engine.computeStateHash(state),
    "state_hash must equal the canonical hash of the pre-evaluation input state");
  assert.notEqual(auth.state_hash, authInternal.state_snapshot_hash,
    "state_hash and state_snapshot_hash must differ: evaluation changes state");
  assert.equal(auth.policy_id, "a".repeat(64));
  assert.equal(auth.expiry, authInternal.expires_at);
  assert.equal(auth.issued_at, 1000);
  assert.ok(auth.alg === "Ed25519" || auth.alg === "HMAC-SHA256");
  assert.ok(typeof auth.kid === "string" && auth.kid.length > 0);
  assert.ok(typeof auth.signature === "string" && auth.signature.length > 0);
});

test("verification success", () => {
  const { out } = allowOutput();
  const auth = out.authorization;
  const result = verifyAuthorization(auth, {
    now: 1010,
    expectedIssuer: "issuer-A",
    expectedAudience: "rp-A",
    expectedPolicyId: "a".repeat(64),
    consumedAuthIds: []
  });

  assert.equal(result.status, "ok");
  assert.equal(result.ok, true);
  assert.deepEqual(result.violations, []);
});

test("verifyAuthorization success with Ed25519 keyset", () => {
  const auth = signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: "issuer-A",
      audience: "rp-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "a".repeat(64),
      decision: "ALLOW",
      issued_at: 1000,
      expiry: 1060,
      kid: "2026-01"
    },
    TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.privateKey
  );
  const result = verifyAuthorization(auth, {
    now: 1010,
    expectedIssuer: "issuer-A",
    expectedAudience: "rp-A",
    expectedPolicyId: "a".repeat(64),
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(result.status, "ok");
});

test("expiry failure", () => {
  const { out } = allowOutput();
  const auth = out.authorization;
  const result = verifyAuthorization(auth, { now: auth.expiry });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_EXPIRED"));
});

test("replay protection (simulated consumed id)", () => {
  const { out } = allowOutput();
  const auth = out.authorization;
  const result = verifyAuthorization(auth, { now: 1010, consumedAuthIds: [auth.auth_id] });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_REPLAY"));
});

test("issuer mismatch", () => {
  const { out } = allowOutput();
  const result = verifyAuthorization(out.authorization, { now: 1010, expectedIssuer: "issuer-B" });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_ISSUER_MISMATCH"));
});

test("audience mismatch", () => {
  const { out } = allowOutput();
  const result = verifyAuthorization(out.authorization, { now: 1010, expectedAudience: "rp-B" });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_AUDIENCE_MISMATCH"));
});

test("policy mismatch", () => {
  const { out } = allowOutput();
  const result = verifyAuthorization(out.authorization, { now: 1010, expectedPolicyId: "b".repeat(64) });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_POLICY_ID_MISMATCH"));
});

test("decision != ALLOW => invalid", () => {
  const { out } = allowOutput();
  const auth = { ...out.authorization, decision: "DENY" as const };
  const result = verifyAuthorization(auth, { now: 1010 });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_DECISION_INVALID"));
});

test("missing mandatory field => invalid", () => {
  const { out } = allowOutput();
  const auth = { ...out.authorization, issued_at: undefined as unknown as number };
  const result = verifyAuthorization(auth, { now: 1010 });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_MISSING_FIELD"));
});

test("unknown kid => invalid", () => {
  const auth = signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: "issuer-A",
      audience: "rp-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "a".repeat(64),
      decision: "ALLOW",
      issued_at: 1000,
      expiry: 1060,
      kid: "2026-01"
    },
    TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.privateKey
  );
  const result = verifyAuthorization({ ...auth, kid: "missing-kid" }, {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_KID_UNKNOWN"));
});

test("legacy HMAC-SHA256 path: verifyAuthorization accepts HMAC artifact via legacyHmacSecret (deprecated)", () => {
  // HMAC-SHA256 is the deprecated legacy verification path.
  // Ed25519 with trustedKeySets is the standard path for all new integrations.
  // This test exists to guarantee backward compatibility only; do not model new code after it.
  const { out } = allowOutput(); // engine defaults to HMAC-SHA256 signing
  const auth = out.authorization;
  if (auth.alg !== "HMAC-SHA256") {
    // Engine has been reconfigured to Ed25519; HMAC legacy test not applicable.
    return;
  }
  const result = verifyAuthorization(auth, {
    now: 1010,
    legacyHmacSecret: "test-secret-must-be-at-least-32-chars!!",
    requireSignatureVerification: true,
  });
  assert.equal(result.status, "ok",
    "legacy HMAC-SHA256 path must still verify for backward compatibility");
  assert.deepEqual(result.violations, []);
});

test("legacy HMAC-SHA256 path: HMAC verification fails when legacyHmacSecret is absent (deprecated)", () => {
  // Without legacyHmacSecret the HMAC path cannot verify. This is intentional:
  // the legacy path must never activate silently — it requires explicit configuration.
  const { out } = allowOutput();
  const auth = out.authorization;
  if (auth.alg !== "HMAC-SHA256") {
    return;
  }
  const result = verifyAuthorization(auth, {
    now: 1010,
    requireSignatureVerification: true,
  });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_TRUST_MISSING"),
    "missing legacyHmacSecret must produce AUTH_TRUST_MISSING");
});

test("unknown alg => invalid", () => {
  const auth = signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: "issuer-A",
      audience: "rp-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "a".repeat(64),
      decision: "ALLOW",
      issued_at: 1000,
      expiry: 1060,
      kid: "2026-01"
    },
    TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.privateKey
  );
  const result = verifyAuthorization({ ...auth, alg: "Unknown" as any }, {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_ALG_UNSUPPORTED"));
});

test("signature invalid after mutation", () => {
  const auth = signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: "issuer-A",
      audience: "rp-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "a".repeat(64),
      decision: "ALLOW",
      issued_at: 1000,
      expiry: 1060,
      kid: "2026-01"
    },
    TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.privateKey
  );
  const result = verifyAuthorization({ ...auth, state_hash: "c".repeat(64) }, {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
});
