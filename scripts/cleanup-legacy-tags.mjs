#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";

const GIT_DIR = process.env.GIT_DIR || ".git";

const KEEP_PATTERN = /^(core|cli|conformance|guard|sdk|langgraph|crewai|autogen|openai-agents|openclaw)-v\d+\.\d+\.\d+$/;
const LEGACY_GLOBAL_PATTERN = /^v\d+\.\d+\.\d+$/;
const CONFIRM_TOKEN = "DELETE_LEGACY_TAGS";

function collectRefTags(dir, prefix = "") {
  const tags = [];
  if (!existsSync(dir)) return tags;
  for (const entry of readdirSync(dir)) {
    const full = `${dir}/${entry}`;
    const name = prefix ? `${prefix}/${entry}` : entry;
    const stat = statSync(full);
    if (stat.isDirectory()) {
      tags.push(...collectRefTags(full, name));
    } else {
      tags.push(name);
    }
  }
  return tags;
}

function collectPackedTags(packedPath) {
  if (!existsSync(packedPath)) return [];
  const tags = [];
  const lines = readFileSync(packedPath, "utf8").split("\n");
  for (const line of lines) {
    if (!line || line.startsWith("#") || line.startsWith("^")) continue;
    const parts = line.trim().split(" ");
    if (parts.length !== 2) continue;
    const ref = parts[1];
    if (ref.startsWith("refs/tags/")) {
      tags.push(ref.replace("refs/tags/", ""));
    }
  }
  return tags;
}

function getTags() {
  const tags = new Set();
  collectRefTags(`${GIT_DIR}/refs/tags`).forEach((t) => tags.add(t));
  collectPackedTags(`${GIT_DIR}/packed-refs`).forEach((t) => tags.add(t));
  return Array.from(tags).sort();
}

function discoverLegacy(tags) {
  return tags.filter((t) => LEGACY_GLOBAL_PATTERN.test(t) && !KEEP_PATTERN.test(t));
}

function parseFlags(argv) {
  const flags = new Set();
  let confirm = "";
  for (const arg of argv) {
    if (arg.startsWith("--confirm=")) {
      confirm = arg.split("=", 2)[1];
    } else {
      flags.add(arg);
    }
  }
  return { flags, confirm };
}

function requireConfirmation(confirm) {
  if (confirm !== CONFIRM_TOKEN) {
    console.error(
      `Refusing to proceed: missing --confirm=${CONFIRM_TOKEN}. Dry-run is the default.`
    );
    process.exit(1);
  }
}

function deleteLocal(tags) {
  for (const tag of tags) {
    console.log(`Deleting local tag ${tag}`);
    execFileSync("git", ["tag", "-d", tag], { stdio: "inherit" });
  }
}

function deleteRemote(tags) {
  for (const tag of tags) {
    console.log(`Deleting remote tag ${tag}`);
    execFileSync("git", ["push", "origin", `:refs/tags/${tag}`], {
      stdio: "inherit",
    });
  }
}

function main() {
  const { flags, confirm } = parseFlags(process.argv.slice(2));
  const apply = flags.has("--apply");
  const applyLocal = apply || flags.has("--apply-local");
  const applyRemote = flags.has("--apply-remote");
  const printRemote = flags.has("--print-remote") || applyRemote || !applyLocal;

  const tags = getTags();
  const legacy = discoverLegacy(tags);

  console.log("Cleanup plan for legacy global tags (pattern vX.Y.Z)\n");

  if (legacy.length === 0) {
    console.log("No legacy global tags found. Nothing to do.");
    return;
  }

  console.log("Legacy tags to remove:");
  legacy.forEach((t) => console.log(`- ${t}`));

  const localCmds = legacy.map((t) => `git tag -d ${t}`);
  const remoteCmds = legacy.map((t) => `git push origin :refs/tags/${t}`);

  if (!applyLocal && !applyRemote && !apply) {
    console.log("\nDry run (no deletions performed).");
    console.log("\nLocal delete commands:");
    localCmds.forEach((c) => console.log(c));
    if (printRemote) {
      console.log("\nRemote delete commands (NOT run by default):");
      remoteCmds.forEach((c) => console.log(c));
    }
    console.log(
      `\nTo apply local deletions: node scripts/cleanup-legacy-tags.mjs --apply-local --confirm=${CONFIRM_TOKEN}`
    );
    console.log(
      `To apply local + remote: node scripts/cleanup-legacy-tags.mjs --apply-local --apply-remote --confirm=${CONFIRM_TOKEN}`
    );
    return;
  }

  if (applyLocal || applyRemote) {
    requireConfirmation(confirm);
  }

  if (applyLocal) {
    deleteLocal(legacy);
  }

  if (applyRemote) {
    deleteRemote(legacy);
  } else if (printRemote) {
    console.log("\nRemote delete commands (not executed):");
    remoteCmds.forEach((c) => console.log(c));
  }
}

main();
