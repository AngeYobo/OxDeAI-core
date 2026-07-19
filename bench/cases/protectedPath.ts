import { verifyAuthorization, verifyEnvelope } from "@oxdeai/core";
import { createProtectedPathFixture } from "../fixtures";

export const name = "protectedPath";

function cloneStateShallow<T extends object>(state: T): T {
  return {
    ...(state as Record<string, unknown>),
    budget: {
      ...(state as any).budget,
      budget_limit: { ...(state as any).budget.budget_limit },
      spent_in_period: { ...(state as any).budget.spent_in_period },
    },
    replay: {
      ...(state as any).replay,
      nonces: { ...((state as any).replay?.nonces ?? {}) },
    },
    velocity: {
      ...(state as any).velocity,
      counters: { ...((state as any).velocity?.counters ?? {}) },
    },
    concurrency: {
      ...(state as any).concurrency,
      active: { ...((state as any).concurrency?.active ?? {}) },
      active_auths: { ...((state as any).concurrency?.active_auths ?? {}) },
    },
  } as T;
}

export function create(seed: number, envelopeMode: "strict" | "best-effort"): () => unknown {
  const fx = createProtectedPathFixture(seed);
  const baseState = cloneStateShallow(fx.state);
  const actionType = fx.intent.action_type;
  const target = fx.intent.target;
  const amount = Number(fx.intent.amount);
  const verifyAuthOpts = {
    now: 1_700_000_000,
    expectedIssuer: "bench-issuer",
    expectedAudience: "bench-rp",
    expectedPolicyId: fx.policyId,
    consumedAuthIds: [] as string[],
    requireSignatureVerification: true,
    legacyHmacSecret: "bench-hmac-secret",
  };

  return () => {
    const decision = fx.engine.evaluatePure(fx.intent, cloneStateShallow(baseState), fx.intent.timestamp);
    if (decision.decision !== "ALLOW") return 0;

    const authResult = verifyAuthorization(fx.auth, verifyAuthOpts);
    if (authResult.status !== "ok") return 0;

    const envResult = verifyEnvelope(fx.envelopeBytes, {
      mode: envelopeMode,
      expectedPolicyId: fx.policyId,
      requireSignatureVerification: false,
      now: 1_700_000_000,
    });
    if (envResult.status !== "ok" && envResult.status !== "inconclusive") return 0;

    return fx.toolExecute(actionType, target, amount);
  };
}
