// SPDX-License-Identifier: Apache-2.0
/**
 * #301 — unit coverage for the pure issuer-policy authority predicate.
 *
 * The one property this file exists to pin: authority is a PAIR. Two
 * independent membership checks would authorize the Cartesian product, which is
 * strictly more authority than the deployer wrote down.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { isTrustedAuthorizationAuthority } from "@oxdeai/core";
import type { AuthorizationAuthority } from "@oxdeai/core";

const AUTHORITIES: readonly AuthorizationAuthority[] = [
  { issuer: "A", policyId: "P1" },
  { issuer: "B", policyId: "P2" },
];

test("#301 authority: configured pairs match", () => {
  assert.equal(isTrustedAuthorizationAuthority(AUTHORITIES, "A", "P1"), true);
  assert.equal(isTrustedAuthorizationAuthority(AUTHORITIES, "B", "P2"), true);
});

test("#301 authority ANTI-CARTESIAN: cross pairs are NOT authorized", () => {
  // The whole point. A and B are both known issuers; P1 and P2 are both known
  // policies. Independent allow-lists would return true for both of these.
  assert.equal(isTrustedAuthorizationAuthority(AUTHORITIES, "A", "P2"), false);
  assert.equal(isTrustedAuthorizationAuthority(AUTHORITIES, "B", "P1"), false);
});

test("#301 authority ANTI-CARTESIAN: exactly the configured pairs, nothing more", () => {
  const authorized: string[] = [];
  for (const i of ["A", "B"]) {
    for (const p of ["P1", "P2"]) {
      if (isTrustedAuthorizationAuthority(AUTHORITIES, i, p)) authorized.push(`${i}/${p}`);
    }
  }
  assert.deepEqual(authorized, ["A/P1", "B/P2"]);
  assert.equal(
    authorized.length,
    AUTHORITIES.length,
    "must authorize |pairs|, never |issuers| x |policies|"
  );
});

test("#301 authority: an empty list authorizes nothing", () => {
  assert.equal(isTrustedAuthorizationAuthority([], "A", "P1"), false);
});

test("#301 authority: matching is exact — no wildcard, prefix, case folding or trimming", () => {
  for (const [issuer, policyId] of [
    ["*", "P1"], ["A", "*"], ["a", "P1"], ["A", "p1"],
    ["A ", "P1"], ["A", " P1"], ["A", "P1 "],
    ["AA", "P1"], ["A", "P11"], ["", "P1"], ["A", ""],
  ] as const) {
    assert.equal(
      isTrustedAuthorizationAuthority(AUTHORITIES, issuer, policyId),
      false,
      `"${issuer}"/"${policyId}" must not match`
    );
  }
});

test("#301 authority: hostile inputs fail closed rather than throwing", () => {
  assert.equal(isTrustedAuthorizationAuthority(undefined as unknown as AuthorizationAuthority[], "A", "P1"), false);
  assert.equal(isTrustedAuthorizationAuthority([null as unknown as AuthorizationAuthority], "A", "P1"), false);
  assert.equal(isTrustedAuthorizationAuthority(AUTHORITIES, undefined as unknown as string, "P1"), false);
  assert.equal(isTrustedAuthorizationAuthority(AUTHORITIES, "A", undefined as unknown as string), false);
});

test("#301 authority: prototype keys do not match", () => {
  assert.equal(isTrustedAuthorizationAuthority(AUTHORITIES, "constructor", "toString"), false);
  assert.equal(isTrustedAuthorizationAuthority(AUTHORITIES, "__proto__", "__proto__"), false);
});

test("#301 authority: duplicate pairs grant nothing extra", () => {
  const dup: readonly AuthorizationAuthority[] = [
    { issuer: "A", policyId: "P1" },
    { issuer: "A", policyId: "P1" },
  ];
  assert.equal(isTrustedAuthorizationAuthority(dup, "A", "P1"), true);
  assert.equal(isTrustedAuthorizationAuthority(dup, "A", "P2"), false);
});
