#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

const RELEASE_PACKAGES = {
  core: {
    name: "@oxdeai/core",
    path: "packages/core",
    tagPrefix: "core",
    changelog: "packages/core/CHANGELOG.md",
  },
  sdk: {
    name: "@oxdeai/sdk",
    path: "packages/sdk",
    tagPrefix: "sdk",
    changelog: "packages/sdk/CHANGELOG.md",
  },
  conformance: {
    name: "@oxdeai/conformance",
    path: "packages/conformance",
    tagPrefix: "conformance",
    changelog: "packages/conformance/CHANGELOG.md",
  },
  guard: {
    name: "@oxdeai/guard",
    path: "packages/guard",
    tagPrefix: "guard",
    changelog: "packages/guard/CHANGELOG.md",
  },
  cli: {
    name: "@oxdeai/cli",
    path: "packages/cli",
    tagPrefix: "cli",
    changelog: "packages/cli/CHANGELOG.md",
  },
  langgraph: {
    name: "@oxdeai/langgraph",
    path: "packages/langgraph",
    tagPrefix: "langgraph",
    changelog: "packages/langgraph/CHANGELOG.md",
  },
  crewai: {
    name: "@oxdeai/crewai",
    path: "packages/crewai",
    tagPrefix: "crewai",
    changelog: "packages/crewai/CHANGELOG.md",
  },
  autogen: {
    name: "@oxdeai/autogen",
    path: "packages/autogen",
    tagPrefix: "autogen",
    changelog: "packages/autogen/CHANGELOG.md",
  },
  "openai-agents": {
    name: "@oxdeai/openai-agents",
    path: "packages/openai-agents",
    tagPrefix: "openai-agents",
    changelog: "packages/openai-agents/CHANGELOG.md",
  },
  openclaw: {
    name: "@oxdeai/openclaw",
    path: "packages/openclaw",
    tagPrefix: "openclaw",
    changelog: "packages/openclaw/CHANGELOG.md",
  },
};

const VERSION_RE = /^\d+\.\d+\.\d+$/;

function usage(exitCode = 0) {
  const out = exitCode === 0 ? console.log : console.error;
  out(`Usage:
  node scripts/release-preflight.mjs --package <core|sdk|conformance|guard|cli|langgraph|crewai|autogen|openai-agents|openclaw> [options]

Options:
  --package <name>              Package short name to validate.
  --tag <tag>                   Planned package-scoped tag. Defaults to <package>-v<package.json version>.
  --check-npm                   Check npm registry and fail if package@version is already published.
  --github-release-tag <tag>    Optional planned GitHub release tag; must match the package tag.
  --github-release-title <text> Optional planned GitHub release title; must include package and version.
  --help                        Show this help.
`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") usage(0);
    if (arg === "--check-npm") {
      args.checkNpm = true;
      continue;
    }
    if (arg.startsWith("--") && arg.includes("=")) {
      const [key, ...rest] = arg.slice(2).split("=");
      args[key] = rest.join("=");
      continue;
    }
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const value = argv[i + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`Missing value for --${key}`);
      }
      args[key] = value;
      i += 1;
      continue;
    }
    throw new Error(`Unexpected argument: ${arg}`);
  }
  return args;
}

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", opts.stderr ?? "pipe"],
  }).trim();
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function tagExists(tag) {
  try {
    run("git", ["rev-parse", "-q", "--verify", `refs/tags/${tag}`]);
    return true;
  } catch {
    return false;
  }
}

function worktreeStatus() {
  return run("git", ["status", "--porcelain=v1"]);
}

function npmVersionExists(pkg, version) {
  try {
    const found = run(
      "npm",
      ["view", `${pkg}@${version}`, "version", "--registry=https://registry.npmjs.org"]
    );
    return found === version;
  } catch (err) {
    const output = String(err?.stderr ?? err?.stdout ?? err?.message ?? "");
    if (output.includes("E404") || output.includes("404 Not Found")) {
      return false;
    }
    throw new Error(`Could not determine npm publish state for ${pkg}@${version}`);
  }
}

function changelogHasVersion(path, version) {
  if (!existsSync(path)) return false;
  const escaped = version.replaceAll(".", "\\.");
  const re = new RegExp(`^##\\s+\\[?v?${escaped}\\]?\\b`, "m");
  return re.test(readFileSync(path, "utf8"));
}

function addCheck(checks, ok, name, detail) {
  checks.push({ ok, name, detail });
}

function printChecks(checks) {
  for (const check of checks) {
    const marker = check.ok ? "PASS" : "FAIL";
    console.log(`${marker} ${check.name}${check.detail ? `: ${check.detail}` : ""}`);
  }
}

function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`ERROR ${err.message}`);
    usage(1);
  }

  const shortName = args.package;
  const cfg = RELEASE_PACKAGES[shortName];
  const checks = [];

  addCheck(
    checks,
    Boolean(shortName && cfg),
    "target package is configured for release",
    shortName ? shortName : "missing --package"
  );

  if (!cfg) {
    printChecks(checks);
    console.error("\nRelease preflight FAILED");
    process.exit(1);
  }

  const packageJsonPath = `${cfg.path}/package.json`;
  const packageExists = existsSync(packageJsonPath);
  addCheck(checks, packageExists, "package.json exists", packageJsonPath);

  let pkg = {};
  if (packageExists) {
    try {
      pkg = readJson(packageJsonPath);
    } catch (err) {
      addCheck(checks, false, "package.json parses as JSON", err.message);
    }
  }

  const version = pkg.version;
  const expectedTag = `${cfg.tagPrefix}-v${version}`;
  const plannedTag = args.tag ?? expectedTag;

  addCheck(checks, typeof version === "string" && VERSION_RE.test(version), "package.json version is X.Y.Z", version);
  addCheck(checks, pkg.name === cfg.name, "package name matches release policy", `${pkg.name ?? "(missing)"} expected ${cfg.name}`);
  addCheck(checks, pkg.private !== true, "package is publishable", pkg.private === true ? "private=true" : "private flag absent/false");

  const tagPattern = new RegExp(`^${cfg.tagPrefix}-v\\d+\\.\\d+\\.\\d+$`);
  addCheck(checks, tagPattern.test(plannedTag), "tag uses package-scoped naming", plannedTag);
  addCheck(checks, plannedTag === expectedTag, "tag version matches package.json version", `${plannedTag} expected ${expectedTag}`);
  addCheck(checks, !tagExists(plannedTag), "planned tag does not already exist", plannedTag);

  const status = worktreeStatus();
  addCheck(checks, status.length === 0, "git worktree is clean", status.length === 0 ? "" : status.split("\n").join("; "));

  addCheck(checks, existsSync("pnpm-lock.yaml"), "pnpm lockfile exists", "pnpm-lock.yaml");
  const lockStatus = status
    .split("\n")
    .filter((line) => line.includes("pnpm-lock.yaml"));
  addCheck(checks, lockStatus.length === 0, "pnpm lockfile has no uncommitted drift", lockStatus.join("; "));

  addCheck(checks, changelogHasVersion(cfg.changelog, version), "changelog contains target version", `${cfg.changelog} ${version}`);

  if (args["github-release-tag"] !== undefined) {
    addCheck(
      checks,
      args["github-release-tag"] === plannedTag,
      "GitHub release tag metadata matches planned tag",
      `${args["github-release-tag"]} expected ${plannedTag}`
    );
  }

  if (args["github-release-title"] !== undefined) {
    const title = args["github-release-title"];
    const hasPackage = title.includes(shortName) || title.includes(cfg.name);
    const hasVersion = title.includes(version);
    addCheck(
      checks,
      hasPackage && hasVersion,
      "GitHub release title metadata includes package and version",
      title
    );
  }

  if (args.checkNpm) {
    const exists = npmVersionExists(cfg.name, version);
    addCheck(checks, !exists, "npm package version is not already published", `${cfg.name}@${version}`);
  }

  console.log("OxDeAI release preflight\n========================\n");
  console.log(`package: ${cfg.name}`);
  console.log(`path:    ${cfg.path}`);
  console.log(`version: ${version ?? "(missing)"}`);
  console.log(`tag:     ${plannedTag}`);
  console.log("");

  printChecks(checks);

  const failed = checks.filter((check) => !check.ok);
  if (failed.length > 0) {
    console.error(`\nRelease preflight FAILED (${failed.length} failure${failed.length === 1 ? "" : "s"})`);
    process.exit(1);
  }

  console.log("\nRelease preflight PASSED");
}

main();
