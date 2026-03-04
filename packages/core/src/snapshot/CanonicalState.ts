import type { CanonicalState as CanonicalStateType } from "../types/state.js";

/** @public */
export type CanonicalState = CanonicalStateType;

/** @public */
export function createCanonicalState(args: {
  formatVersion?: 1;
  engineVersion: string;
  modules: Record<string, unknown>;
  policyId: string;
}): CanonicalState {
  return {
    formatVersion: args.formatVersion ?? 1,
    engineVersion: args.engineVersion,
    policyId: args.policyId,
    modules: { ...args.modules }
  };
}

/** @public */
export function withModuleState(state: CanonicalState, moduleId: string, payload: unknown): CanonicalState {
  return {
    ...state,
    modules: {
      ...state.modules,
      [moduleId]: payload
    }
  };
}
