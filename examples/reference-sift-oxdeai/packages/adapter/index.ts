// SPDX-License-Identifier: Apache-2.0
/**
 * Sift → OxDeAI adapter.
 *
 * Converts a Sift receipt + adapter-supplied params + state into a signed
 * AuthorizationV1 payload. This is the only path through which a Sift
 * governance decision becomes an executable authorization.
 *
 * Pipeline (fail-closed at every step):
 *   1. verifyReceiptWithKeyStore  — signature + freshness + decision
 *   2. normalizeIntent            — tool binding + param normalization
 *   3. normalizeState             — state normalization
 *   4. receiptToAuthorization     — binding construction (unsigned)
 *   5. Ed25519 sign               — sign the canonical signing payload
 *
 * The returned `authorization.signature.sig` is a real Ed25519 signature
 * over the canonical signing payload. The PEP verifies this before executing.
 */

import { sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import {
  verifyReceiptWithKeyStore,
  normalizeIntent,
  normalizeState,
  receiptToAuthorization,
  SiftHttpKeyStore,
} from "@oxdeai/sift";
import { siftCanonicalJsonBytes, b64uEncode } from "../../shared/canonical.js";
import type { AdapterInput, AdapterResult } from "../../shared/types.js";

// ─── Configuration ────────────────────────────────────────────────────────────

export interface AdapterConfig {
  /** URL of the Sift (or mock-sift) JWKS endpoint. */
  siftJwksUrl: string;
  /** URL of the Sift (or mock-sift) KRL endpoint. */
  siftKrlUrl: string;
  /** Ed25519 private key used to sign the AuthorizationV1 payload. */
  privateKey: KeyObject;
  /** Key ID for the signing key (maps to adapter's JWKS if published). */
  keyId: string;
  /** Issuer claim in the AuthorizationV1 (e.g. "adapter-issuer"). */
  issuer: string;
  /** Audience claim — must match the PEP's configured audience. */
  audience: string;
  /** TTL in seconds for issued authorizations. Defaults to 30. */
  ttlSeconds?: number;
  /** Custom fetch for test injection. Defaults to globalThis.fetch. */
  fetch?: typeof globalThis.fetch;
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

export class SiftAdapter {
  private readonly keyStore: SiftHttpKeyStore;
  private readonly config: AdapterConfig;

  constructor(config: AdapterConfig) {
    this.config = config;
    // ── KRL integrity mode ───────────────────────────────────────────────────
    // TRANSITION MODE: This example uses the default signed_preferred mode,
    // which accepts unsigned KRLs via transport trust as a fallback.
    // This is a transition posture — NOT production-grade revocation integrity.
    //
    // For production deployments, configure signed_required with verifyKrl,
    // KrlWatermarkStore, and SignedKrlCache to fully close RT-TRUST-2.
    // See packages/sift/README.md (Migration guide) for the production pattern.
    //
    // Example production wiring (not activated here — requires KRL signing keys):
    //
    //   import { verifySignedKrl } from "@oxdeai/core";
    //   import { createFileBackedKrlWatermarkStore, createFileBackedSignedKrlCache } from "@oxdeai/sift";
    //   krlMode: "signed_required",
    //   verifyKrl: (payload, ctx) => {
    //     const result = verifySignedKrl(payload, { trustedKeySets: myKrlSigningKeySets, ...ctx });
    //     if (!result.ok) return result;
    //     const krl = payload as { issuer: string; krl_version: number };
    //     return { ...result, accepted: { issuer: krl.issuer, krl_version: krl.krl_version } };
    //   },
    //   krlWatermarkStore: createFileBackedKrlWatermarkStore("/var/app/krl-watermark.json"),
    //   signedKrlCache: createFileBackedSignedKrlCache("/var/app/krl-lkg.json"),
    //
    this.keyStore = new SiftHttpKeyStore({
      jwksUrl: config.siftJwksUrl,
      krlUrl: config.siftKrlUrl,
      fetch: config.fetch,
      // krlMode defaults to "signed_preferred" — see comment above.
    });
  }

  async adapt(input: AdapterInput): Promise<AdapterResult> {
    const { kidAndReceipt, params, state, now } = input;

    // ── 1. Verify receipt ────────────────────────────────────────────────────
    // Enforces: signature integrity, version, receipt_hash, ALLOW decision,
    // and freshness (default maxAgeMs = 30_000).
    const verifyResult = await verifyReceiptWithKeyStore(kidAndReceipt.receipt, {
      kid: kidAndReceipt.kid,
      keyStore: this.keyStore,
      requireAllowDecision: true,
    });
    if (!verifyResult.ok) {
      return { ok: false, code: verifyResult.code, message: verifyResult.message };
    }

    // ── 2. Normalize intent ──────────────────────────────────────────────────
    // Binds receipt.tool to adapter-supplied params.
    // PARAMETER BINDING: params are NOT cryptographically bound by the receipt.
    // See normalizeIntent JSDoc and docs/adapters/sift.md §"Parameter Binding".
    const intentResult = normalizeIntent({
      receipt: verifyResult.receipt,
      params,
    });
    if (!intentResult.ok) {
      return { ok: false, code: intentResult.code, message: intentResult.message };
    }

    // ── 3. Normalize state ───────────────────────────────────────────────────
    const stateResult = normalizeState({ state });
    if (!stateResult.ok) {
      return { ok: false, code: stateResult.code, message: stateResult.message };
    }

    // ── 4. Build unsigned AuthorizationV1 ────────────────────────────────────
    const authResult = receiptToAuthorization({
      receipt: verifyResult.receipt,
      intent: intentResult.intent,
      state: stateResult.state,
      issuer: this.config.issuer,
      audience: this.config.audience,
      keyId: this.config.keyId,
      ttlSeconds: this.config.ttlSeconds ?? 30,
      now,
    });
    if (!authResult.ok) {
      return { ok: false, code: authResult.code, message: authResult.message };
    }

    // ── 5. Sign ───────────────────────────────────────────────────────────────
    // The signing payload is AuthorizationV1 minus signature.sig.
    // siftCanonicalJsonBytes sorts keys — the PEP reconstructs the same bytes.
    const preimage = siftCanonicalJsonBytes(authResult.signingPayload);
    const sigBuf = sign(null, preimage, this.config.privateKey);

    return {
      ok: true,
      authorization: {
        ...authResult.authorization,
        signature: {
          ...authResult.authorization.signature,
          sig: b64uEncode(sigBuf),
        },
      },
      intent: intentResult.intent,
      state: stateResult.state,
    };
  }
}
