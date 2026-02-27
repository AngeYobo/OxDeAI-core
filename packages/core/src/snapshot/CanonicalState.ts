import type { CanonicalState as CanonicalStateType, StateHash } from "../types/state.js";

export type CanonicalState = CanonicalStateType;
export type { StateHash };

export function createCanonicalState(args: {
  engineVersion: string;
  moduleStates: Record<string, Uint8Array>;
  globalStateHash: StateHash;
  policyId?: string;
}): CanonicalState {
  return {
    engineVersion: args.engineVersion,
    policyId: args.policyId,
    moduleStates: { ...args.moduleStates },
    globalStateHash: args.globalStateHash
  };
}

export function withModuleState(state: CanonicalState, moduleId: string, bytes: Uint8Array): CanonicalState {
  return {
    ...state,
    moduleStates: {
      ...state.moduleStates,
      [moduleId]: bytes
    }
  };
}
