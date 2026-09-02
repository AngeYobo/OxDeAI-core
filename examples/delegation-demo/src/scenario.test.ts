// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";

import { runScenario } from "./scenario.js";
import { CHILD_ACTION_1_UNITS, CHILD_ACTION_2_UNITS } from "./policy.js";

// Regression for the demo's OxDeAIGuard constructions omitting the required
// trustedKeySets: OxDeAIGuard throws OxDeAIGuardConfigurationError at
// construction time if any is missing, so runScenario() itself would reject
// before returning any steps. This test therefore also proves parent auth,
// child ALLOW, and child DENY all still resolve for their intended reasons.

test("delegation demo: parent auth ALLOW, child within scope ALLOW, child over scope DENY", async () => {
  const steps = await runScenario();

  const parentAuth = steps.find((s) => s.auth?.authType === "engine");
  assert.ok(parentAuth?.auth, "parent engine authorization step missing");
  assert.equal(parentAuth.auth.decision, "ALLOW");

  const childAllow = steps.find(
    (s) => s.auth?.agentId === "B" && s.auth.amountUnits === CHILD_ACTION_1_UNITS
  );
  assert.ok(childAllow?.auth, "child action 1 step missing");
  assert.equal(childAllow.auth.decision, "ALLOW");
  assert.equal(childAllow.auth.executionStatus, "executed");

  const childDeny = steps.find(
    (s) => s.auth?.agentId === "B" && s.auth.amountUnits === CHILD_ACTION_2_UNITS
  );
  assert.ok(childDeny?.auth, "child action 2 step missing");
  assert.equal(childDeny.auth.decision, "DENY");
  assert.equal(childDeny.auth.executionStatus, "blocked_before_execution");
  assert.match(
    childDeny.auth.reason,
    /exceeds delegation max_amount/,
    `expected the delegation scope.max_amount violation, got: ${childDeny.auth.reason}`
  );
});
