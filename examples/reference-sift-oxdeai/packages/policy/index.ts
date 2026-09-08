// SPDX-License-Identifier: Apache-2.0
/**
 * Policy rules for the reference deployment.
 *
 * In production, policy configuration is loaded from a signed manifest or
 * a configuration service. This reference implementation uses a static set
 * to keep the invariant code-level auditable.
 */

// ─── Known policies ───────────────────────────────────────────────────────────

/**
 * The set of policy IDs that this PEP accepts.
 * An AuthorizationV1 whose `policy_id` is NOT in this set is rejected,
 * even if the signature is valid.
 */
export const KNOWN_POLICIES = new Set([
  "transfer-policy-v1",
  "withdraw-policy-v1",
  "read-only-policy-v1",
]);

export function isKnownPolicy(policyId: string): boolean {
  return KNOWN_POLICIES.has(policyId);
}

// ─── Known issuers ────────────────────────────────────────────────────────────

/**
 * Accepted adapter issuers. An AuthorizationV1 whose `issuer` is NOT in
 * this set is rejected even if the signature is valid.
 */
export const KNOWN_ISSUERS = new Set(["adapter-issuer"]);

export function isKnownIssuer(issuer: string): boolean {
  return KNOWN_ISSUERS.has(issuer);
}

// ─── Issuer-policy authority (pairs, not a product) ───────────────────────────

/**
 * Which issuer is authorized for which policy, as complete pairs.
 *
 * ⚠️ Deliberately NOT `KNOWN_ISSUERS × KNOWN_POLICIES`. Those two sets answer
 * narrower adapter-level questions and, combined, would authorize the Cartesian
 * product of every issuer with every policy. Enforcement authority is
 * enumerated pair-by-pair so that adding a second issuer later cannot silently
 * grant it every existing policy.
 *
 * This deployment authorizes one adapter issuer for three policies, written out
 * rather than generated — the point of the list is that a reviewer can read
 * exactly what is authorized.
 */
export const TRUSTED_AUTHORIZATION_AUTHORITIES: readonly { issuer: string; policyId: string }[] = [
  { issuer: "adapter-issuer", policyId: "transfer-policy-v1" },
  { issuer: "adapter-issuer", policyId: "withdraw-policy-v1" },
  { issuer: "adapter-issuer", policyId: "read-only-policy-v1" },
];
