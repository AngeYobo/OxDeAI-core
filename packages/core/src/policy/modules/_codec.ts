import { createHash } from "node:crypto";
import { deserialize as v8Deserialize, serialize as v8Serialize } from "node:v8";
import type { ModuleStateCodec, State, StateHash } from "../../types/state.js";
import { stableStringify } from "../../utils/stableStringify.js";

export function statelessModuleCodec(moduleId: string): ModuleStateCodec {
  const serialize = (): Uint8Array =>
    new TextEncoder().encode(stableStringify({ moduleId, state: {} }));

  const codec: ModuleStateCodec = {
    serialize,
    deserialize(_bytes: Uint8Array): void {
      // Stateless module codec: no internal mutable state to hydrate.
    },
    stateHash(): StateHash {
      return createHash("sha256").update(codec.serialize()).digest("hex");
    }
  };
  return codec;
}

export type StateBoundModuleCodec = {
  serializeState: (state: State) => Uint8Array;
  deserializeState: (state: State, bytes: Uint8Array) => void;
  stateHash: (state: State) => StateHash;
};

function makeStateCodec<T>(
  pick: (state: State) => T,
  apply: (state: State, value: T) => void
): StateBoundModuleCodec {
  return {
    serializeState(state: State): Uint8Array {
      const value = pick(state);
      return Uint8Array.from(v8Serialize(value));
    },
    deserializeState(state: State, bytes: Uint8Array): void {
      const value = v8Deserialize(Buffer.from(bytes)) as T;
      apply(state, value);
    },
    stateHash(state: State): StateHash {
      const payload = stableStringify(pick(state));
      return createHash("sha256").update(payload, "utf8").digest("hex");
    }
  };
}

export const MODULE_CODECS: Record<string, StateBoundModuleCodec> = {
  AllowlistModule: makeStateCodec(
    (s) => s.allowlists,
    (s, v) => {
      s.allowlists = v;
    }
  ),
  BudgetModule: makeStateCodec(
    (s) => ({ budget: s.budget, max_amount_per_action: s.max_amount_per_action }),
    (s, v) => {
      s.budget = v.budget;
      s.max_amount_per_action = v.max_amount_per_action;
    }
  ),
  ConcurrencyModule: makeStateCodec(
    (s) => s.concurrency,
    (s, v) => {
      s.concurrency = v;
    }
  ),
  KillSwitchModule: makeStateCodec(
    (s) => s.kill_switch,
    (s, v) => {
      s.kill_switch = v;
    }
  ),
  RecursionDepthModule: makeStateCodec(
    (s) => s.recursion,
    (s, v) => {
      s.recursion = v;
    }
  ),
  ReplayModule: makeStateCodec(
    (s) => s.replay,
    (s, v) => {
      s.replay = v;
    }
  ),
  ToolAmplificationModule: makeStateCodec(
    (s) => s.tool_limits ?? { window_seconds: 0, max_calls: {}, calls: {} },
    (s, v) => {
      s.tool_limits = v;
    }
  ),
  VelocityModule: makeStateCodec(
    (s) => s.velocity,
    (s, v) => {
      s.velocity = v;
    }
  )
};
