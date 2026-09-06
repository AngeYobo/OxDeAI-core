// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from "node:crypto";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { DelegationV1, DelegationScope } from "../types/delegation.js";
import { SIGNING_DOMAINS, signEd25519 } from "../crypto/signatures.js";
import { delegationParentHash, delegationSigningPayload } from "../verification/verifyDelegation.js";

// ── CreateDelegationParams ────────────────────────────────────────────────────

/** @public */
export type CreateDelegationParams = {
  /** Agent or principal receiving delegated authority. */
  delegatee: string;
  /** Scope granted to the delegatee — must be a subset of the parent scope. */
  scope: DelegationScope;
  /** Expiry in unix seconds. Must be <= parent.expiry. */
  expiry: number;
  /** Key ID used to sign this delegation. Must be resolvable in trustedKeySets at verify time. */
  kid: string;
  /** Issuer of this delegation (typically the delegating principal's identifier). */
  issuer?: string;
  /** Audience for this delegation (typically the delegatee's identifier). */
  audience?: string;
  /** Override the delegation_id (defaults to randomUUID()). */
  delegationId?: string;
  /** Override issued_at in unix seconds (defaults to Math.floor(Date.now() / 1000)). */
  issuedAt?: number;
};

// ── createDelegation ──────────────────────────────────────────────────────────

/**
 * Create a signed DelegationV1 artifact from a parent AuthorizationV1.
 *
 * The parent hash is computed automatically.
 * The delegator is set to parent.audience.
 * The policy_id is inherited from parent.policy_id.
 * The signature is computed over the canonical signing payload using Ed25519.
 *
 * `scope` is signed exactly as supplied — a field the caller omits stays
 * absent from the signed artifact. It is not materialized against a parent
 * scope here. Effective-scope inheritance for an omitted field (see
 * `resolveEffectiveChildScope` in `verifyDelegation.ts`) is resolved only at
 * verification time, so existing signed bytes and signatures are unaffected
 * by that resolution.
 *
 * @public
 */
export function createDelegation(
  parent: AuthorizationV1,
  params: CreateDelegationParams,
  privateKeyPem: string
): DelegationV1 {
  const now = params.issuedAt ?? Math.floor(Date.now() / 1000);
  const scope: DelegationScope = {};
  if (params.scope.tools !== undefined) scope.tools = params.scope.tools;
  if (params.scope.max_amount !== undefined) scope.max_amount = params.scope.max_amount;
  if (params.scope.max_actions !== undefined) scope.max_actions = params.scope.max_actions;
  if (params.scope.max_depth !== undefined) scope.max_depth = params.scope.max_depth;
  const unsigned: DelegationV1 = {
    delegation_id: params.delegationId ?? randomUUID(),
    issuer: params.issuer ?? parent.audience,
    audience: params.audience ?? params.delegatee,
    parent_auth_hash: delegationParentHash(parent),
    delegator: parent.audience,
    delegatee: params.delegatee,
    scope,
    policy_id: parent.policy_id,
    issued_at: now,
    expiry: params.expiry,
    alg: "Ed25519",
    kid: params.kid,
    signature: "",
  };
  const signature = signEd25519(SIGNING_DOMAINS.DELEGATION_V1, delegationSigningPayload(unsigned), privateKeyPem);
  return { ...unsigned, signature };
}
