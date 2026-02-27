import { stableSortedKeys } from "../utils/stableSort.js";
import { stableStringify } from "../utils/stableStringify.js";
import type { CanonicalState } from "./CanonicalState.js";

type CanonicalStateWire = {
  engineVersion: string;
  policyId: string | null;
  moduleStates: Record<string, string>;
  globalStateHash: string;
};

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64"));
}

export function encodeCanonicalState(state: CanonicalState): Uint8Array {
  const moduleStates: Record<string, string> = {};
  for (const id of stableSortedKeys(state.moduleStates)) {
    moduleStates[id] = bytesToBase64(state.moduleStates[id]);
  }

  const wire: CanonicalStateWire = {
    engineVersion: state.engineVersion,
    policyId: state.policyId ?? null,
    moduleStates,
    globalStateHash: state.globalStateHash
  };

  return new TextEncoder().encode(stableStringify(wire));
}

export function decodeCanonicalState(bytes: Uint8Array): CanonicalState {
  const json = new TextDecoder().decode(bytes);
  const parsed = JSON.parse(json) as CanonicalStateWire;
  const moduleStates: Record<string, Uint8Array> = {};
  for (const id of stableSortedKeys(parsed.moduleStates)) {
    moduleStates[id] = base64ToBytes(parsed.moduleStates[id]);
  }
  return {
    engineVersion: parsed.engineVersion,
    policyId: parsed.policyId ?? undefined,
    moduleStates,
    globalStateHash: parsed.globalStateHash
  };
}
