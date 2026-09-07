// SPDX-License-Identifier: Apache-2.0
/**
 * #301 — issuer-policy authority for the DELEGATION ROOT.
 *
 * `opts.delegation.parentAuth` is caller-supplied. A signature under a trusted
 * key proves who signed; it does not prove that issuer may issue for the
 * claimed `policy_id`. Until the parent is BOTH authenticated and authorized,
 * none of its fields (audience, policy_id, expiry) may act as the child's trust
 * reference — `verifyDelegationChain` consumes exactly those fields.
 *
 * The child must never inherit authority the parent never had.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  signAuthorizationEd25519,
  createDelegation,
} from "@oxdeai/core";
import type { AuthorizationAuthority, AuthorizationV1, DelegationV1, KeySet } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import {
  OxDeAIAuthorityError,
  OxDeAIAuthorizationError,
  OxDeAIGuardConfigurationError,
} from "../errors.js";
import type { OxDeAIGuardConfig, ProposedAction } from "../types.js";

const KP_A = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const KP_B = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const ISSUER_A = "deleg-issuer-A";
const ISSUER_B = "deleg-issuer-B";
const POLICY_1 = "deleg-policy-P1";
const POLICY_2 = "deleg-policy-P2";

const KEYSET_A: KeySet = {
  issuer: ISSUER_A, version: "v1",
  keys: [{ kid: "ka", alg: "Ed25519", public_key: KP_A.publicKey.toString() }],
};
const KEYSET_B: KeySet = {
  issuer: ISSUER_B, version: "v1",
  keys: [{ kid: "kb", alg: "Ed25519", public_key: KP_B.publicKey.toString() }],
};

/** Authorizes A/P1 and B/P2 only. A/P2 and B/P1 must be rejected. */
const AUTHORITIES: readonly AuthorizationAuthority[] = [
  { issuer: ISSUER_A, policyId: POLICY_1 },
  { issuer: ISSUER_B, policyId: POLICY_2 },
];

const T_NOW = Math.floor(Date.now() / 1000);
const PARENT_SCOPE = { tools: ["provision_gpu"], max_amount: 1_000_000n };

let seq = 0;
function makeParentAuth(issuer: string, policyId: string): AuthorizationV1 {
  const isA = issuer === ISSUER_A;
  return signAuthorizationEd25519(
    {
      auth_id: `deleg-parent-${issuer}-${policyId}-${seq++}`,
      issuer,
      audience: "agent-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: policyId,
      decision: "ALLOW",
      issued_at: T_NOW - 60,
      expiry: T_NOW + 900,
      kid: isA ? "ka" : "kb",
    },
    (isA ? KP_A : KP_B).privateKey.toString()
  );
}

function makeChild(parentAuth: AuthorizationV1, issuer: string): DelegationV1 {
  const isA = issuer === ISSUER_A;
  return createDelegation(
    parentAuth,
    {
      delegatee: "agent-B",
      issuer,
      scope: { tools: ["provision_gpu"], max_amount: 500_000n },
      expiry: T_NOW + 300,
      kid: isA ? "ka" : "kb",
    },
    (isA ? KP_A : KP_B).privateKey.toString()
  );
}

function makeConfig(overrides?: Partial<OxDeAIGuardConfig>): OxDeAIGuardConfig {
  const state = buildState({
    agent_id: "agent-B",
    allow_action_types: ["PROVISION"],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
  return {
    engine: new PolicyEngine({
      policy_version: "v1",
      engine_secret: "test-secret-must-be-at-least-32-chars!!",
      authorization_signing_alg: "Ed25519",
      authorization_signing_kid: "ka",
      authorization_issuer: ISSUER_A,
      authorization_audience: "agent-A",
      authorization_ttl_seconds: 600,
      authorization_private_key_pem: KP_A.privateKey.toString(),
      ...RECOMMENDED_TRUSTED_TIME_PROFILE,
    }),
    getState: () => ({ state, version: 0 }),
    setState: () => true,
    trustedKeySets: [KEYSET_A, KEYSET_B],
    expectedAudience: "agent-A",
    trustedDelegationAuthorities: AUTHORITIES,
    ...overrides,
  };
}

const ACTION: ProposedAction = {
  name: "provision_gpu",
  args: { asset: "a100" },
  estimatedCost: 0,
  context: { agent_id: "agent-B", target: "gpu-pool" },
  timestampSeconds: T_NOW,
};

async function run(config: OxDeAIGuardConfig, parentAuth: AuthorizationV1, delegation: DelegationV1) {
  const guard = OxDeAIGuard(config);
  let executed = false;
  let error: unknown;
  try {
    await guard(ACTION, async () => { executed = true; return "ok"; },
      { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } });
  } catch (err) {
    error = err;
  }
  return { executed, error };
}

test("#301 delegation: authorized parent (A/P1) establishes a valid delegation root", async () => {
  const parentAuth = makeParentAuth(ISSUER_A, POLICY_1);
  const { executed, error } = await run(makeConfig(), parentAuth, makeChild(parentAuth, ISSUER_A));
  assert.equal(error, undefined, `expected success, got: ${String(error)}`);
  assert.equal(executed, true);
});

test("#301 delegation ANTI-CARTESIAN: validly signed parent A/P2 is rejected; execute never called", async () => {
  const parentAuth = makeParentAuth(ISSUER_A, POLICY_2);
  const { executed, error } = await run(makeConfig(), parentAuth, makeChild(parentAuth, ISSUER_A));
  assert.equal(executed, false, "execute must never run for an unauthorized parent");
  assert.ok(error instanceof OxDeAIAuthorityError, `expected OxDeAIAuthorityError, got ${String(error)}`);
  assert.match(String((error as Error).message), /not authorized for its claimed policy_id/);
});

test("#301 delegation ANTI-CARTESIAN: second trusted issuer B claiming A's policy P1 is rejected", async () => {
  const parentAuth = makeParentAuth(ISSUER_B, POLICY_1);
  const { executed, error } = await run(makeConfig(), parentAuth, makeChild(parentAuth, ISSUER_B));
  assert.equal(executed, false);
  assert.ok(error instanceof OxDeAIAuthorityError);
});

test("#301 delegation: a self-consistent chain under a registered-but-unauthorized issuer fails AT AUTHORITY", async () => {
  // Parent and child are valid and mutually consistent; the ONLY defect is that
  // A is not authorized for P2. The failure must be the authority error, not a
  // chain/scope error — proving rejection happened before verifyDelegationChain
  // was allowed to trust parent fields.
  const parentAuth = makeParentAuth(ISSUER_A, POLICY_2);
  const { executed, error } = await run(makeConfig(), parentAuth, makeChild(parentAuth, ISSUER_A));
  assert.equal(executed, false);
  assert.ok(error instanceof OxDeAIAuthorityError, `expected authority rejection, got ${String(error)}`);
  assert.equal((error as Error).name, "OxDeAIAuthorityError");
});

test("#301 delegation: child cannot inherit authority from an unauthorized parent even when its own scope is valid", async () => {
  const parentAuth = makeParentAuth(ISSUER_A, POLICY_2);
  const child = createDelegation(
    parentAuth,
    { delegatee: "agent-B", issuer: ISSUER_A, scope: { tools: ["provision_gpu"], max_amount: 1n }, expiry: T_NOW + 60, kid: "ka" },
    KP_A.privateKey.toString()
  );
  const { executed, error } = await run(makeConfig(), parentAuth, child);
  assert.equal(executed, false);
  assert.ok(error instanceof OxDeAIAuthorityError);
});

test("#301 delegation: ordering — authority rejection precedes chain verification", async () => {
  // Parent unauthorized AND the child chain broken (expiry exceeds parent). If
  // the chain were verified first the error would be a delegation error;
  // authority must win, proving parent fields were not yet trusted.
  const parentAuth = makeParentAuth(ISSUER_A, POLICY_2);
  const badChild = createDelegation(
    parentAuth,
    { delegatee: "agent-B", issuer: ISSUER_A, scope: { tools: ["provision_gpu"] }, expiry: parentAuth.expiry + 10_000, kid: "ka" },
    KP_A.privateKey.toString()
  );
  const { executed, error } = await run(makeConfig(), parentAuth, badChild);
  assert.equal(executed, false);
  assert.ok(
    error instanceof OxDeAIAuthorityError,
    `authority must be evaluated before the chain; got ${String((error as Error)?.name)}`
  );
});

// ── Mixed failure: authority must never mask an authentication defect ───────

test("#301 delegation MIXED FAILURE: unauthorized pair AND invalid signature is a verification failure, not an authority denial", async () => {
  // The parent is defective twice over: its (issuer, policy_id) pair is not
  // authorized, AND it is signed with a key the trust anchors do not hold.
  // `verifyAuthorization` aggregates both violations.
  //
  // `OxDeAIAuthorityError` asserts that the artifact AUTHENTICATED and merely
  // lacked authority. Emitting it here would state something false and would let
  // the authority violation mask a forged signature, so the boundary must fall
  // back to the generic — and stricter — verification failure.
  const rogue = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const forgedUnauthorizedParent = signAuthorizationEd25519(
    {
      auth_id: `deleg-parent-mixed-${seq++}`,
      issuer: ISSUER_A,
      audience: "agent-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: POLICY_2,          // A is NOT authorized for P2
      decision: "ALLOW",
      issued_at: T_NOW - 60,
      expiry: T_NOW + 900,
      kid: "ka",
    },
    rogue.privateKey.toString()      // ...and the signature does not verify
  );

  const events: { stage: string; boundaryFailure: string }[] = [];
  const config = makeConfig({
    onBoundaryEvent: (e) => { events.push({ stage: e.stage, boundaryFailure: e.boundaryFailure }); },
  });

  const { executed, error } = await run(
    config,
    forgedUnauthorizedParent,
    makeChild(forgedUnauthorizedParent, ISSUER_A)
  );

  assert.equal(executed, false, "execute must never run");
  assert.ok(error instanceof OxDeAIAuthorizationError, `expected OxDeAIAuthorizationError, got ${String(error)}`);
  assert.ok(
    !(error instanceof OxDeAIAuthorityError),
    "a mixed failure must NOT be reported as an authority denial — that would claim the artifact authenticated"
  );
  assert.match(String((error as Error).message), /Parent authorization verification failed/);

  assert.equal(events.length, 1);
  assert.equal(events[0]?.boundaryFailure, "AUTHORIZATION_VERIFICATION_FAILED");
  assert.notEqual(events[0]?.boundaryFailure, "AUTHORIZATION_AUTHORITY_DENIED");
});

test("#301 delegation MIXED FAILURE: unauthorized pair AND wrong audience is a verification failure, not an authority denial", async () => {
  // Same rule with a non-cryptographic second defect: the audience does not
  // match the guard's independently configured expectation.
  const parent = signAuthorizationEd25519(
    {
      auth_id: `deleg-parent-mixed-aud-${seq++}`,
      issuer: ISSUER_A,
      audience: "agent-WRONG",     // guard expects "agent-A"
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: POLICY_2,         // and A is not authorized for P2
      decision: "ALLOW",
      issued_at: T_NOW - 60,
      expiry: T_NOW + 900,
      kid: "ka",
    },
    KP_A.privateKey.toString()     // validly signed this time
  );

  const { executed, error } = await run(makeConfig(), parent, makeChild(parent, ISSUER_A));

  assert.equal(executed, false);
  assert.ok(error instanceof OxDeAIAuthorizationError);
  assert.ok(!(error instanceof OxDeAIAuthorityError), "authority must not mask the audience mismatch");
});

test("#301 delegation: MISSING authority configuration fails closed at call time", async () => {
  const parentAuth = makeParentAuth(ISSUER_A, POLICY_1);
  const config = makeConfig();
  delete (config as { trustedDelegationAuthorities?: unknown }).trustedDelegationAuthorities;
  const { executed, error } = await run(config, parentAuth, makeChild(parentAuth, ISSUER_A));
  assert.equal(executed, false);
  assert.ok(error instanceof OxDeAIGuardConfigurationError, `expected configuration error, got ${String(error)}`);
  assert.match(String((error as Error).message), /trustedDelegationAuthorities is required/);
});

test("#301 delegation: EMPTY authority list is valid configuration that authorizes no root", async () => {
  const parentAuth = makeParentAuth(ISSUER_A, POLICY_1);
  const { executed, error } = await run(
    makeConfig({ trustedDelegationAuthorities: [] }), parentAuth, makeChild(parentAuth, ISSUER_A)
  );
  assert.equal(executed, false);
  assert.ok(error instanceof OxDeAIAuthorityError, `expected authority rejection, got ${String(error)}`);
  assert.ok(!(error instanceof OxDeAIGuardConfigurationError), "empty must differ from missing");
});

test("#301 delegation: authority rejection is reported on onBoundaryEvent with its own failure code", async () => {
  const parentAuth = makeParentAuth(ISSUER_A, POLICY_2);
  const events: { stage: string; boundaryFailure: string }[] = [];
  const config = makeConfig({
    onBoundaryEvent: (e) => { events.push({ stage: e.stage, boundaryFailure: e.boundaryFailure }); },
  });
  const { executed } = await run(config, parentAuth, makeChild(parentAuth, ISSUER_A));
  assert.equal(executed, false);
  assert.equal(events.length, 1);
  assert.equal(events[0]?.boundaryFailure, "AUTHORIZATION_AUTHORITY_DENIED");
});
