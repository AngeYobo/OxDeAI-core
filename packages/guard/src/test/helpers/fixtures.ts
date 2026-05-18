// SPDX-License-Identifier: Apache-2.0
import { generateKeyPairSync } from "node:crypto";
import {
  signAuthorizationEd25519,
  createDelegation,
} from "@oxdeai/core";
import type { KeySet, AuthorizationV1, DelegationV1, DelegationScope } from "@oxdeai/core";

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

export function signAuth(overrides: Partial<AuthorizationV1> = {}): AuthorizationV1 {
  const issued_at = overrides.issued_at ?? nowSeconds();
  return signAuthorizationEd25519(
    {
      auth_id: overrides.auth_id ?? `auth-${issued_at}`,
      issuer: overrides.issuer ?? TEST_KEYSET.issuer,
      audience: overrides.audience ?? "aud-test",
      intent_hash: overrides.intent_hash ?? "i".repeat(64),
      state_hash: overrides.state_hash ?? "s".repeat(64),
      policy_id: overrides.policy_id ?? "p".repeat(64),
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
