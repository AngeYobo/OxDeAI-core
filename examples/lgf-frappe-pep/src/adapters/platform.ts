// SPDX-License-Identifier: Apache-2.0
import type { PepMode } from "../config.js";

export type PlatformExecutionContext = {
  correlationId: string;
  mode: PepMode;
  authId: string;
  expectedAudience: string;
};

export type PlatformExecutionResult = {
  resource_id: string;
  details?: Record<string, unknown>;
};

export interface PlatformAdapter {
  readonly name: string;
  execute(
    action: string,
    payload: unknown,
    context: PlatformExecutionContext,
  ): Promise<PlatformExecutionResult>;
}
