import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

// `examples/gpu-guard/demo.mjs` is the only plain-JavaScript example, so it is
// invisible to `pnpm typecheck` (there is no `allowJs`/`checkJs`) and nothing
// else executes it. Running it is the only thing that can detect it drifting
// away from the core API — which is how it silently broke against the required
// trusted-time options and the `evaluatePure` signature.
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const DEMO_PATH = path.join(REPO_ROOT, "examples", "gpu-guard", "demo.mjs");

test("gpu-guard demo runs against the current core API and authorizes its sample intent", () => {
  // execFileSync throws on a non-zero exit, so this also asserts the demo runs.
  const stdout = execFileSync(process.execPath, [DEMO_PATH], { encoding: "utf8" });

  assert.match(stdout, /^decision: ALLOW$/m);
});
