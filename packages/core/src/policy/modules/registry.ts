import type { StateBoundModuleCodec } from "./_codec.js";
import { MODULE_CODECS as BASE_MODULE_CODECS } from "./_codec.js";

// v0.5 registry boundary for module codecs.
// Keep ids stable; PolicyEngine sorts keys before hashing/serialization.
export const MODULE_CODECS: Record<string, StateBoundModuleCodec> = {
  AllowlistModule: BASE_MODULE_CODECS.AllowlistModule,
  BudgetModule: BASE_MODULE_CODECS.BudgetModule,
  ConcurrencyModule: BASE_MODULE_CODECS.ConcurrencyModule,
  KillSwitchModule: BASE_MODULE_CODECS.KillSwitchModule,
  RecursionDepthModule: BASE_MODULE_CODECS.RecursionDepthModule,
  ReplayModule: BASE_MODULE_CODECS.ReplayModule,
  ToolAmplificationModule: BASE_MODULE_CODECS.ToolAmplificationModule,
  VelocityModule: BASE_MODULE_CODECS.VelocityModule
};
