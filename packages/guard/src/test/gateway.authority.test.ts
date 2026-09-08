// SPDX-License-Identifier: Apache-2.0
/**
 * #301 — issuer-policy authority at the PEP gateway.
 *
 * The gateway is the highest-risk boundary: the AuthorizationV1 arrives inside
 * an untrusted request. These tests pin the property that A VALID SIGNATURE IS
 * NOT POLICY AUTHORITY — every artifact below is correctly signed by a key the
 * gateway trusts, and is rejected anyway when its (issuer, policy_id) pair was
 * not independently authorized by deployer configuration.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { sha256HexFromJson, signAuthorizationEd25519 } from "@oxdeai/core";
import type { AuthorizationV1, KeySet } from "@oxdeai/core";
import { createPepGatewayExecutor } from "../gateway.js";

// ── Two independently trusted issuers; authority is what differs ────────────

const KP_A = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const KP_B = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const ISSUER_A = "issuer-A";
const ISSUER_B = "issuer-B";
const POLICY_1 = "policy-P1";
const POLICY_2 = "policy-P2";

const KEYSET_A: KeySet = {
  issuer: ISSUER_A, version: "v1",
  keys: [{ kid: "ka", alg: "Ed25519", public_key: KP_A.publicKey.toString() }],
};
const KEYSET_B: KeySet = {
  issuer: ISSUER_B, version: "v1",
  keys: [{ kid: "kb", alg: "Ed25519", public_key: KP_B.publicKey.toString() }],
};

const AUDIENCE = "gateway-authority-audience";
const TOKEN = "internal-token-for-tests";
const ACTION = { type: "EXECUTE", tool: "payments.charge", params: { amount: "1" } };

/**
 * Authorizes exactly A/P1 and B/P2 — and therefore must NOT authorize A/P2 or
 * B/P1, the Cartesian product an independent-allow-list design would permit.
 */
const AUTHORITIES = [
  { issuer: ISSUER_A, policyId: POLICY_1 },
  { issuer: ISSUER_B, policyId: POLICY_2 },
] as const;

let seq = 0;
function signFor(issuer: string, policyId: string): AuthorizationV1 {
  const isA = issuer === ISSUER_A;
  const issued_at = Math.floor(Date.now() / 1000);
  return signAuthorizationEd25519(
    {
      auth_id: `authority-auth-${issuer}-${policyId}-${seq++}`,
      issuer,
      audience: AUDIENCE,
      intent_hash: sha256HexFromJson(ACTION),
      state_hash: "s".repeat(64),
      policy_id: policyId,
      decision: "ALLOW",
      issued_at,
      expiry: issued_at + 600,
      kid: isA ? "ka" : "kb",
      nonce: "1",
      capability: "exec",
    },
    (isA ? KP_A : KP_B).privateKey.toString()
  );
}

function makeGateway(
  authorities: readonly { issuer: string; policyId: string }[],
  onUpstream: () => void
) {
  return createPepGatewayExecutor({
    expectedAudience: AUDIENCE,
    trustedKeySets: [KEYSET_A, KEYSET_B],
    trustedAuthorizationAuthorities: authorities,
    internalExecutorToken: TOKEN,
    executeUpstream: async () => {
      onUpstream();
      return { status: 200, body: { ok: true, executed: true } };
    },
  });
}

// ── Authorized pairs execute ────────────────────────────────────────────────

test("#301 gateway: authorized (issuer, policy) pair with a valid signature reaches upstream", async () => {
  let calls = 0;
  const result = await makeGateway(AUTHORITIES, () => calls++)(
    { action: ACTION, authorization: signFor(ISSUER_A, POLICY_1) }
  );
  assert.equal(result.status, 200);
  assert.equal(result.body.executed, true);
  assert.equal(result.upstreamCalled, true);
  assert.equal(calls, 1);
});

test("#301 gateway: the second configured pair is independently authorized", async () => {
  let calls = 0;
  const result = await makeGateway(AUTHORITIES, () => calls++)(
    { action: ACTION, authorization: signFor(ISSUER_B, POLICY_2) }
  );
  assert.equal(result.status, 200);
  assert.equal(calls, 1);
});

// ── Anti-Cartesian-product ──────────────────────────────────────────────────

test("#301 gateway ANTI-CARTESIAN: trusted issuer A signing unauthorized policy P2 is rejected; upstream never called", async () => {
  let calls = 0;
  const result = await makeGateway(AUTHORITIES, () => calls++)(
    { action: ACTION, authorization: signFor(ISSUER_A, POLICY_2) }
  );
  assert.equal(result.status, 403);
  assert.equal(result.body.executed, false);
  assert.equal(result.upstreamCalled, false, "authority rejection must never reach upstream");
  assert.equal(calls, 0);
  assert.match(
    String(result.body.reason),
    /AUTH_ISSUER_POLICY_NOT_AUTHORIZED/,
    "must report an authority rejection, not a scalar expectation mismatch"
  );
});

test("#301 gateway ANTI-CARTESIAN: trusted issuer B signing unauthorized policy P1 is rejected", async () => {
  let calls = 0;
  const result = await makeGateway(AUTHORITIES, () => calls++)(
    { action: ACTION, authorization: signFor(ISSUER_B, POLICY_1) }
  );
  assert.equal(result.status, 403);
  assert.equal(result.upstreamCalled, false);
  assert.equal(calls, 0);
  assert.match(String(result.body.reason), /AUTH_ISSUER_POLICY_NOT_AUTHORIZED/);
});

test("#301 gateway ANTI-CARTESIAN: the four pairs form a matrix, not a product", async () => {
  const observed: Record<string, number> = {};
  for (const [issuer, policyId] of [
    [ISSUER_A, POLICY_1], [ISSUER_A, POLICY_2],
    [ISSUER_B, POLICY_1], [ISSUER_B, POLICY_2],
  ] as const) {
    const result = await makeGateway(AUTHORITIES, () => {})(
      { action: ACTION, authorization: signFor(issuer, policyId) }
    );
    observed[`${issuer}/${policyId}`] = result.status;
  }
  assert.deepEqual(observed, {
    [`${ISSUER_A}/${POLICY_1}`]: 200,
    [`${ISSUER_A}/${POLICY_2}`]: 403,
    [`${ISSUER_B}/${POLICY_1}`]: 403,
    [`${ISSUER_B}/${POLICY_2}`]: 200,
  });
});

test("#301 gateway: a policy authorized only for another issuer is rejected for this one", async () => {
  const result = await makeGateway([{ issuer: ISSUER_A, policyId: POLICY_1 }], () => {
    throw new Error("upstream must not be called");
  })({ action: ACTION, authorization: signFor(ISSUER_B, POLICY_1) });
  assert.equal(result.status, 403);
  assert.equal(result.upstreamCalled, false);
});

// ── Missing vs empty configuration ──────────────────────────────────────────

test("#301 gateway: an explicitly EMPTY authority list constructs, and authorizes nothing", async () => {
  let calls = 0;
  const gateway = makeGateway([], () => calls++);
  for (const [issuer, policyId] of [[ISSUER_A, POLICY_1], [ISSUER_B, POLICY_2]] as const) {
    const result = await gateway({ action: ACTION, authorization: signFor(issuer, policyId) });
    assert.equal(result.status, 403, `${issuer}/${policyId} must be denied`);
    assert.equal(result.upstreamCalled, false);
  }
  assert.equal(calls, 0);
});

test("#301 gateway: MISSING authority configuration fails deterministically at construction", () => {
  assert.throws(
    () =>
      createPepGatewayExecutor({
        expectedAudience: AUDIENCE,
        trustedKeySets: [KEYSET_A],
        internalExecutorToken: TOKEN,
        executeUpstream: async () => ({ status: 200 }),
        // trustedAuthorizationAuthorities deliberately omitted
      } as unknown as Parameters<typeof createPepGatewayExecutor>[0]),
    /trustedAuthorizationAuthorities is required/,
    "absent authority configuration must never be read as unconstrained"
  );
});

test("#301 gateway: missing and empty authority configuration are DISTINCT states", () => {
  assert.throws(() =>
    createPepGatewayExecutor({
      expectedAudience: AUDIENCE,
      trustedKeySets: [KEYSET_A],
      internalExecutorToken: TOKEN,
      executeUpstream: async () => ({ status: 200 }),
    } as unknown as Parameters<typeof createPepGatewayExecutor>[0])
  );
  assert.doesNotThrow(() =>
    createPepGatewayExecutor({
      expectedAudience: AUDIENCE,
      trustedKeySets: [KEYSET_A],
      trustedAuthorizationAuthorities: [],
      internalExecutorToken: TOKEN,
      executeUpstream: async () => ({ status: 200 }),
    })
  );
});

// ── Authority neither weakens nor is weakened by signature trust ────────────

test("#301 gateway: an authorized pair with an UNTRUSTED signing key is still rejected", async () => {
  const rogue = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const issued_at = Math.floor(Date.now() / 1000);
  const forged = signAuthorizationEd25519(
    {
      auth_id: "forged-1", issuer: ISSUER_A, audience: AUDIENCE,
      intent_hash: sha256HexFromJson(ACTION), state_hash: "s".repeat(64),
      policy_id: POLICY_1, // an AUTHORIZED pair
      decision: "ALLOW", issued_at, expiry: issued_at + 600,
      kid: "ka", nonce: "1", capability: "exec",
    },
    rogue.privateKey.toString() // wrong key
  );
  const result = await makeGateway(AUTHORITIES, () => {
    throw new Error("upstream must not be called");
  })({ action: ACTION, authorization: forged });

  assert.equal(result.status, 403);
  assert.equal(result.upstreamCalled, false);
  assert.match(String(result.body.reason), /AUTH_SIGNATURE_INVALID/);
});
