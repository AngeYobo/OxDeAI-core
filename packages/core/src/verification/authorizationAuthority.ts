// SPDX-License-Identifier: Apache-2.0

/**
 * One deployer-authorized (issuer, policyId) pair.
 *
 * ⚠️ This is NOT key trust. `trustedKeySets` answers a different question:
 *
 * ```text
 * trustedKeySets                  -> "which signing keys are trusted for this claimed issuer?"
 * trustedAuthorizationAuthorities -> "which authenticated issuer is authorized for which policy?"
 * ```
 *
 * A valid signature proves that a trusted key belonging to the claimed issuer
 * signed the artifact. It does NOT prove that this issuer is permitted to issue
 * authorizations for the claimed `policy_id`. Both questions must be answered
 * before an externally supplied authorization is accepted.
 *
 * The pair is the unit of authority, and it is deliberately not decomposable
 * into two independent allow-lists. Given configuration:
 *
 * ```text
 * { issuer: "A", policyId: "P1" }
 * { issuer: "B", policyId: "P2" }
 * ```
 *
 * `A+P1` and `B+P2` are authorized; `A+P2` and `B+P1` are NOT. Two independent
 * lists (`issuers: [A, B]`, `policies: [P1, P2]`) would authorize the Cartesian
 * product of four pairs, which is strictly more authority than the deployer
 * configured. Do not refactor this into independent membership checks.
 *
 * @public
 */
export type AuthorizationAuthority = {
  /** Exact `issuer` value the authenticated artifact must carry. */
  readonly issuer: string;
  /** Exact `policy_id` value that issuer is authorized to issue for. */
  readonly policyId: string;
};

/**
 * True only when `(issuer, policyId)` appears as a complete pair in
 * `authorities`.
 *
 * Matching is exact string equality on both members, evaluated together. There
 * is no wildcard, no prefix match, no regex, no case folding and no
 * normalization: an authority list is deployer-controlled configuration, and a
 * matching rule that accepts more than what was written down is
 * indistinguishable from a misconfiguration at the point where it matters.
 *
 * Fail-closed by construction:
 *
 * ```text
 * authorities = []   -> false for every pair   (configured, authorizes nothing)
 * ```
 *
 * An empty list is a valid configuration that authorizes no pairs. Absence of
 * configuration is a different condition and MUST be rejected by the calling
 * boundary before it reaches this function — this predicate cannot distinguish
 * "deployer authorized nothing" from "deployer configured nothing", and callers
 * must not collapse the two.
 *
 * @public
 */
export function isTrustedAuthorizationAuthority(
  authorities: readonly AuthorizationAuthority[],
  issuer: string,
  policyId: string
): boolean {
  if (!Array.isArray(authorities)) return false;
  if (typeof issuer !== "string" || issuer.length === 0) return false;
  if (typeof policyId !== "string" || policyId.length === 0) return false;

  for (const authority of authorities) {
    if (
      authority !== null &&
      typeof authority === "object" &&
      authority.issuer === issuer &&
      authority.policyId === policyId
    ) {
      return true;
    }
  }
  return false;
}
