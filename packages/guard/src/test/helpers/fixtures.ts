// SPDX-License-Identifier: Apache-2.0
import { generateKeyPairSync } from "node:crypto";
import {
  signAuthorizationEd25519,
  createDelegation,
} from "@oxdeai/core";
import type { AuthorizationAuthority, KeySet, AuthorizationV1, DelegationV1, DelegationScope } from "@oxdeai/core";

export const TEST_KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

export const TEST_KEYSET: KeySet = {
  issuer: "test-issuer",
  version: "v1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: TEST_KEYPAIR.publicKey.toString() }],
};

export const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Default `policy_id` minted by {@link signAuth}. */
export const FIXTURE_POLICY_ID = "p".repeat(64);

/**
 * Delegation-root authority for the guard test fixtures (#301).
 *
 * Two explicit pairs, both under the single fixture issuer — still pair-shaped,
 * never `issuers x policies`. A delegation call without this configured fails
 * closed, which `guard.delegation.authority.test.ts` asserts directly.
 */
export const DELEGATION_AUTHORITIES: readonly AuthorizationAuthority[] = [
  { issuer: TEST_KEYSET.issuer, policyId: FIXTURE_POLICY_ID },
  { issuer: TEST_KEYSET.issuer, policyId: "policy-1" },
];

export function signAuth(overrides: Partial<AuthorizationV1> = {}): AuthorizationV1 {
  const issued_at = overrides.issued_at ?? nowSeconds();
  return signAuthorizationEd25519(
    {
      auth_id: overrides.auth_id ?? `auth-${issued_at}`,
      issuer: overrides.issuer ?? TEST_KEYSET.issuer,
      audience: overrides.audience ?? "aud-test",
      intent_hash: overrides.intent_hash ?? "i".repeat(64),
      state_hash: overrides.state_hash ?? "s".repeat(64),
      policy_id: overrides.policy_id ?? FIXTURE_POLICY_ID,
      decision: "ALLOW",
      issued_at,
      expiry: overrides.expiry ?? issued_at + 600,
      kid: overrides.kid ?? "k1",
      nonce: overrides.nonce ?? "1",
      capability: overrides.capability ?? "exec",
    },
    TEST_KEYPAIR.privateKey.toString()
  );
}

export function makeParentAuthWithScope(
  _scope: DelegationScope,
  overrides: Partial<AuthorizationV1> = {}
): AuthorizationV1 {
  return signAuth(overrides);
}

export function makeDelegationWithScope(parent: AuthorizationV1, scope: DelegationV1["scope"]): DelegationV1 {
  return createDelegation(
    parent,
    {
      delegatee: parent.audience,
      scope,
      expiry: parent.expiry,
      kid: "k1",
      audience: parent.audience,
      issuer: TEST_KEYSET.issuer,
    },
    TEST_KEYPAIR.privateKey.toString()
  );
}
