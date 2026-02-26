import test from "node:test";
import assert from "node:assert/strict";

import { HashChainedLog } from "@oxdeai/core";

test("audit log exposes snapshot/headHash/verify and is tamper-evident", () => {
  const log = new HashChainedLog();

  const h0 = log.headHash();
  assert.equal(typeof h0, "string");
  assert.equal(log.verify(), true);

  log.append({ type: "INTENT_RECEIVED", intent_hash: "h1", agent_id: "a1", timestamp: 1 });
  log.append({ type: "DECISION", intent_hash: "h1", decision: "ALLOW", reasons: [], policy_version: "v0.1", timestamp: 1 });

  const snap = log.snapshot();
  assert.equal(Array.isArray(snap), true);
  assert.equal(snap.length, 2);
  assert.equal(log.verify(), true);

  // Tamper attempt: modifying returned snapshot must NOT affect internal chain
  (snap as any)[0].agent_id = "MUTATED";
  assert.equal(log.verify(), true);

  // But internal head must be stable and non-genesis now
  const h1 = log.headHash();
  assert.notEqual(h1, "GENESIS");
});
