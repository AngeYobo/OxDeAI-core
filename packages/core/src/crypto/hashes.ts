import { createHash } from "node:crypto";
import type { Intent } from "../types/intent.js";
import type { State } from "../types/state.js";
import type { Authorization } from "../types/authorization.js";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function canonicalize(value: unknown): unknown {
  if (value === undefined) return null;
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    const out: Record<string, unknown> = {};
    for (const k of keys) out[k] = canonicalize(value[k]);
    return out;
  }
  return value;
}
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}
export function sha256HexFromJson(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}
export function intentHash(intent: Intent): string {
  const { signature: _sig, ...rest } = intent;
  void _sig;
  return sha256HexFromJson(rest);
}
export function stateSnapshotHash(state: State): string {
  return sha256HexFromJson(state);
}
export function authPayloadString(auth: Omit<Authorization, "engine_signature">): string {
  return canonicalJson(auth);
}
