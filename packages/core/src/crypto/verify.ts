import { timingSafeEqual } from "node:crypto";
import { engineSignHmac } from "./sign.js";

function hexToBuf(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

export function engineVerifyHmac(
  payload: unknown,
  signatureHex: string,
  secret: string
): boolean {
  try {
    const expected = engineSignHmac(payload, secret);
    const a = hexToBuf(expected);
    const b = hexToBuf(signatureHex);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
