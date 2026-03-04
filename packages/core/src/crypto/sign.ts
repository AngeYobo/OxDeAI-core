import { createHmac } from "node:crypto";
import { canonicalJson } from "./hashes.js";

/** @public */
export function engineSignHmac(payload: unknown, secret: string): string {
  const msg = canonicalJson(payload);
  return createHmac("sha256", secret).update(msg).digest("hex");
}
