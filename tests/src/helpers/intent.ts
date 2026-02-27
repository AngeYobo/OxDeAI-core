import type { Intent } from "@oxdeai/core";

export function makeIntent(overrides: Partial<Intent> = {}): Intent {
  const merged = {
    intent_id: "intent-1",
    agent_id: "agent-1",
    action_type: "PAYMENT",
    type: "EXECUTE",
    nonce: 1n,
    amount: 1n,
    target: "merchant",
    timestamp: 1_700_000_000,
    metadata_hash: "0x" + "0".repeat(64),
    signature: "sig",
    depth: 0,
    tool_call: false,
    ...overrides
  };

  if (merged.type === "RELEASE" && !merged.authorization_id) {
    merged.authorization_id = "test-auth-id";
  }

  return merged as Intent;
}
