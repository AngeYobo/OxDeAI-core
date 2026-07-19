// SPDX-License-Identifier: Apache-2.0

/**
 * Recommended trusted-time profile.
 *
 * Matches docs/spec/core/trusted-time-v1.md §5 and
 * packages/conformance/vectors/trusted-time.json.
 *
 * This is a recommended deployment profile, not a protocol fallback.
 * Production integrations must choose their policy explicitly.
 *
 * @public
 */
export const RECOMMENDED_TRUSTED_TIME_PROFILE = {
  maxClockSkewSeconds: 300,
  maxIntentAgeSeconds: 300,
} as const;
