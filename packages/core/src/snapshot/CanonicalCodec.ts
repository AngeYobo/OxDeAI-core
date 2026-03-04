import { canonicalJson } from "../crypto/hashes.js";
import type { CanonicalState } from "./CanonicalState.js";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function assertCanonicalState(value: unknown): CanonicalState {
  if (!isObject(value) || Array.isArray(value)) {
    throw new Error("invalid canonical state");
  }

  if (!("formatVersion" in value)) {
    throw new Error("invalid canonical state: missing formatVersion");
  }
  if (value.formatVersion !== 1) {
    throw new Error("invalid canonical state: unsupported formatVersion");
  }
  if (typeof value.engineVersion !== "string") {
    throw new Error("invalid canonical state: engineVersion");
  }
  if (typeof value.policyId !== "string") {
    throw new Error("invalid canonical state: policyId");
  }
  if (!isObject(value.modules) || Array.isArray(value.modules)) {
    throw new Error("invalid canonical state: modules");
  }

  return {
    formatVersion: 1,
    engineVersion: value.engineVersion,
    policyId: value.policyId,
    modules: value.modules
  };
}

/** @public */
export function encodeCanonicalState(state: CanonicalState): Uint8Array {
  const normalized = assertCanonicalState(state);
  return new TextEncoder().encode(canonicalJson(normalized));
}

/** @public */
export function decodeCanonicalState(bytes: Uint8Array): CanonicalState {
  const json = new TextDecoder().decode(bytes);
  const parsed = JSON.parse(json) as unknown;
  return assertCanonicalState(parsed);
}
