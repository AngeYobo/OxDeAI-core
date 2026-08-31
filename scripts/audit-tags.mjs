#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";

const GIT_DIR = process.env.GIT_DIR || ".git";

const KEEP_PATTERN = /^(core|cli|conformance|guard|sdk|langgraph|crewai|autogen|openai-agents|openclaw)-v\d+\.\d+\.\d+$/;
const LEGACY_GLOBAL_PATTERN = /^v\d+\.\d+\.\d+$/;
const PACKAGE_LIKE_PATTERN = /^([a-z0-9_-]+)-v\d+\.\d+\.\d+(?:[-\w.]*)?$/i;

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

function classify(tags) {
  const keep = [];
  const legacy = [];
  const suspicious = [];

  for (const tag of tags) {
    if (KEEP_PATTERN.test(tag)) {
      keep.push(tag);
    } else if (LEGACY_GLOBAL_PATTERN.test(tag)) {
      legacy.push(tag);
    } else {
      suspicious.push(tag);
    }
  }

  return { keep, legacy, suspicious };
}

function packageHint(tag) {
  const match = PACKAGE_LIKE_PATTERN.exec(tag);
  if (!match) return "";
  const name = match[1];
  const pkgPath = `packages/${name}/package.json`;
  if (existsSync(pkgPath)) {
    return `(package exists at ${pkgPath})`;
  }
  return "(no matching package found)";
}

function printCategory(title, list, formatter = (x) => x) {
  console.log(`\n${title} (${list.length})`);
  console.log("-".repeat(title.length + 4));
  if (list.length === 0) {
    console.log("(none)");
    return;
  }
  for (const item of list) {
    console.log(formatter(item));
  }
}

function main() {
  const tags = getTags();
  const { keep, legacy, suspicious } = classify(tags);

  console.log("OxDeAI tag audit\n================\n");
  console.log(`Total tags: ${tags.length}`);
  console.log(`Keep (package) tags: ${keep.length}`);
  console.log(`Legacy global tags: ${legacy.length}`);
  console.log(`Suspicious / needs review: ${suspicious.length}`);

  printCategory("keep_package_tags", keep);
  printCategory("legacy_global_tags", legacy);
  printCategory("suspicious_tags", suspicious, (t) => `${t} ${packageHint(t)}`);

  console.log("\nClassification rules:");
  console.log(`- keep:        ${KEEP_PATTERN}`);
  console.log(`- legacy:      ${LEGACY_GLOBAL_PATTERN}`);
  console.log("- suspicious:  everything else (including adapters-v* for now)");
}

main();
