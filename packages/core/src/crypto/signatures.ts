// SPDX-License-Identifier: Apache-2.0
import { createPrivateKey, createPublicKey, createHmac, sign, verify, timingSafeEqual } from "node:crypto";
import { canonicalJson } from "./hashes.js";
import type { KeySet, KeySetKey, SignatureAlgorithm } from "../types/keyset.js";

/** @public */
export const SIGNING_DOMAINS = {
  AUTH_V1:      "OXDEAI_AUTH_V1",
  ENVELOPE_V1:  "OXDEAI_ENVELOPE_V1",
  CHECKPOINT_V1: "OXDEAI_CHECKPOINT_V1",
  DELEGATION_V1: "OXDEAI_DELEGATION_V1",
  KRL_V1:       "OXDEAI_KRL_V1",
} as const;

/** @public */
export type SigningDomain = (typeof SIGNING_DOMAINS)[keyof typeof SIGNING_DOMAINS];

function canonicalBytes(payload: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(payload));
}

/** @public */
export function signatureInput(domain: SigningDomain, payload: unknown): Uint8Array {
  const prefix = new TextEncoder().encode(`${domain}\n`);
  const body = canonicalBytes(payload);
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix, 0);
  out.set(body, prefix.length);
  return out;
}

function normalizePem(key: string): string {
  return key.includes("BEGIN") ? key : Buffer.from(key, "base64").toString("utf8");
}

/** @public */
export function signEd25519(domain: SigningDomain, payload: unknown, privateKeyPem: string): string {
  const key = createPrivateKey(normalizePem(privateKeyPem));
  const sig = sign(null, signatureInput(domain, payload), key);
  return sig.toString("base64");
}

/** @public */
export function verifyEd25519(
  domain: SigningDomain,
  payload: unknown,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  try {
    const key = createPublicKey(normalizePem(publicKeyPem));
    const sig = Buffer.from(signatureBase64, "base64");
    return verify(null, signatureInput(domain, payload), key, sig);
  } catch {
    return false;
  }
}

/** @public */
export function signHmacDomain(domain: SigningDomain, payload: unknown, secret: string): string {
  const msg = Buffer.from(signatureInput(domain, payload));
  return createHmac("sha256", secret).update(msg).digest("hex");
}

/** @public */
export function verifyHmacDomain(
  domain: SigningDomain,
  payload: unknown,
  signatureHex: string,
  secret: string
): boolean {
  try {
    const expected = signHmacDomain(domain, payload, secret);
    const a = Buffer.from(expected, "hex");
    const b = Buffer.from(signatureHex, "hex");
    if (a.length === 0 || a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/** @public */
export function findKeyInKeySets(
  keysets: readonly KeySet[],
  issuer: string,
  kid: string,
  alg: SignatureAlgorithm
): KeySetKey | undefined {
  const ks = keysets.find((k) => k.issuer === issuer);
  if (!ks) return undefined;
  return ks.keys.find((k) => k.kid === kid && k.alg === alg);
}

/** @public */
export function keyIsActiveAt(key: KeySetKey, now: number): boolean {
  if (key.status === "revoked") return false;
  if (key.not_before !== undefined && now < key.not_before) return false;
  if (key.not_after !== undefined && now > key.not_after) return false;
  return true;
}
