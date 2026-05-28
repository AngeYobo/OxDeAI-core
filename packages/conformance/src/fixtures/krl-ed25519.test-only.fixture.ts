// SPDX-License-Identifier: Apache-2.0
/**
 * KRL SIGNING KEY — TEST ONLY — DO NOT USE IN PRODUCTION.
 *
 * Distinct Ed25519 fixture for SignedKRLV1 conformance vectors.
 * Intentionally separate from the AuthorizationV1 / DelegationV1 signing key
 * fixture (ed25519.test-only.fixture.ts) to exercise the trust-domain
 * separation between KRL signing keys and authorization signing keys.
 *
 * kid: "krl-2026-01"
 * issuer (in conformance vectors): "krl.issuer"
 */

export const KRL_TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKPuSm5iCBRfVLXFwMLVWzdRDAI882fQ1XeZqwvBDayT
-----END PRIVATE KEY-----`;

export const KRL_TEST_ONLY_ED25519_PUBLIC_KEY_PEM_DO_NOT_USE_IN_PRODUCTION = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAoNLRsm0uJ8Zb4z9BErD/xcPyN8kK1Y3zTrpdxDGiT2A=
-----END PUBLIC KEY-----`;
