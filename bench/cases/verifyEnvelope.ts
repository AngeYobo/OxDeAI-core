import { BENCHMARK_ENVELOPE_KEY_SET, createFixtureSet } from "../fixtures";
import { verifyEnvelope } from "@oxdeai/core";

export const name = "verifyEnvelope";

export function create(seed: number, mode: "strict" | "best-effort"): () => unknown {
  const fixture = createFixtureSet(seed).complex;

  return () => {
    const out = verifyEnvelope(fixture.envelopeBytes, {
      mode,
      expectedPolicyId: fixture.policy.id,
      trustedKeySets: BENCHMARK_ENVELOPE_KEY_SET,
      requireSignatureVerification: false,
      now: 1_700_000_000,
    });
    return out.status;
  };
}
