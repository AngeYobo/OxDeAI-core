import test from "node:test";
import assert from "node:assert/strict";
import { sha256HexFromJson } from "@oxdeai/core";
import type { Intent } from "@oxdeai/core";

test("intent hashing is stable for same logical object", () => {
  const a: Intent = {
    intent_id: "i1",
    agent_id: "a1",
    action_type: "PAYMENT",
    amount: 1_000_000n,
    asset: "USDC",
    target: "t1",
    timestamp: 1000,
    metadata_hash: "0x" + "0".repeat(64),
    nonce: 1n,
    signature: "sig"
  };
  const b: Intent = { ...a };
  const ha = sha256HexFromJson(a);
  const hb = sha256HexFromJson(b);
  assert.equal(ha, hb);
  assert.equal(ha.length, 64);
});
