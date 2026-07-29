#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { cp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, "..");
const apiExtractor = join(
  repoRoot,
  "packages/core/node_modules/.bin/api-extractor",
);
const fixtureRoot = mkdtempSync(join(tmpdir(), "oxdeai-api-guard-"));
const templateDir = join(fixtureRoot, "template");

const baseDeclaration = `export interface PublicOptions {
  mode: "strict" | "permissive";
  label?: string;
}

export declare class PublicClient {
  evaluate(input: string, options: PublicOptions): PublicOptions;
}
`;

const config = {
  mainEntryPointFilePath: "<projectFolder>/dist/index.d.ts",
  apiReport: {
    enabled: true,
    reportFileName: "fixture.api.md",
    reportFolder: "<projectFolder>/etc",
    reportTempFolder: "<projectFolder>/temp",
  },
  docModel: { enabled: false },
  dtsRollup: { enabled: false },
  messages: {
    compilerMessageReporting: { default: { logLevel: "none" } },
    extractorMessageReporting: { default: { logLevel: "none" } },
    tsdocMessageReporting: { default: { logLevel: "none" } },
  },
};

function runExtractor(projectDir, local = false) {
  const args = [
    "run",
    ...(local ? ["--local"] : []),
    "--config",
    join(projectDir, "api-extractor.json"),
  ];
  return spawnSync(apiExtractor, args, {
    cwd: projectDir,
    encoding: "utf8",
  });
}

function hashNormalizedReport(report) {
  const normalized = report.toString("utf8").replace(/\r\n/g, "\n");
  return createHash("sha256").update(normalized, "utf8").digest("hex");
}

async function prepareTemplate() {
  await mkdir(join(templateDir, "dist"), { recursive: true });
  await mkdir(join(templateDir, "etc"), { recursive: true });
  await mkdir(join(templateDir, "temp"), { recursive: true });
  writeFileSync(join(templateDir, "dist/index.d.ts"), baseDeclaration);
  writeFileSync(
    join(templateDir, "dist/internal.d.ts"),
    "export declare function internalHelper(value: string): string;\n",
  );
  writeFileSync(
    join(templateDir, "api-extractor.json"),
    `${JSON.stringify(config, null, 2)}\n`,
  );
  writeFileSync(
    join(templateDir, "package.json"),
    '{"name":"api-guard-fixture","version":"1.0.0"}\n',
  );
  writeFileSync(
    join(templateDir, "tsconfig.json"),
    '{"compilerOptions":{"strict":true},"include":["dist/**/*.d.ts"]}\n',
  );
  writeFileSync(join(templateDir, "README.md"), "Fixture documentation.\n");

  const baseline = runExtractor(templateDir, true);
  assert.equal(
    baseline.status,
    0,
    `Unable to create fixture baseline: ${baseline.error ?? ""}\n` +
      `${baseline.stdout}${baseline.stderr}`,
  );
}

async function runCase(name, mutate, shouldPass) {
  const projectDir = join(fixtureRoot, name);
  await cp(templateDir, projectDir, { recursive: true });
  await mutate(projectDir);
  const result = runExtractor(projectDir);
  assert.equal(
    result.status === 0,
    shouldPass,
    `${name}: expected API check to ${shouldPass ? "pass" : "fail"}\n` +
      `${result.stdout}${result.stderr}`,
  );
  process.stdout.write(`PASS ${name}\n`);
}

try {
  await prepareTemplate();

  const publicShapeCases = [
    [
      "exported-interface-member",
      (source) =>
        source.replace(
          '  label?: string;\n',
          '  label?: string;\n  timeoutMs: number;\n',
        ),
    ],
    [
      "public-method-signature",
      (source) =>
        source.replace(
          "evaluate(input: string, options: PublicOptions)",
          "evaluate(input: string, options: PublicOptions, retries: number)",
        ),
    ],
    [
      "public-return-type",
      (source) => source.replace("): PublicOptions;", "): Promise<PublicOptions>;"),
    ],
    [
      "exported-union",
      (source) =>
        source.replace(
          '"strict" | "permissive"',
          '"strict" | "permissive" | "audit"',
        ),
    ],
    [
      "exported-optionality",
      (source) => source.replace("label?: string;", "label: string;"),
    ],
  ];

  for (const [name, mutateSource] of publicShapeCases) {
    await runCase(
      name,
      async (projectDir) => {
        const declarationPath = join(projectDir, "dist/index.d.ts");
        writeFileSync(
          declarationPath,
          mutateSource(readFileSync(declarationPath, "utf8")),
        );
      },
      false,
    );
  }

  await runCase(
    "internal-helper",
    async (projectDir) => {
      const declarationPath = join(projectDir, "dist/internal.d.ts");
      const source = readFileSync(declarationPath, "utf8");
      writeFileSync(
        declarationPath,
        source.replace(
          "internalHelper(value: string): string",
          "internalHelper(value: number): number",
        ),
      );
    },
    true,
  );

  await runCase(
    "documentation-only",
    async (projectDir) => {
      writeFileSync(join(projectDir, "README.md"), "Updated documentation.\n");
    },
    true,
  );

  const firstCheck = runExtractor(templateDir);
  const firstReport = readFileSync(join(templateDir, "temp/fixture.api.md"));
  const firstFingerprint = hashNormalizedReport(firstReport);
  const secondCheck = runExtractor(templateDir);
  const secondReport = readFileSync(join(templateDir, "temp/fixture.api.md"));
  const secondFingerprint = hashNormalizedReport(secondReport);

  assert.equal(firstCheck.status, 0, "first deterministic API check failed");
  assert.equal(secondCheck.status, 0, "second deterministic API check failed");
  assert.deepEqual(firstReport, secondReport);
  assert.equal(firstFingerprint, secondFingerprint);
  process.stdout.write("PASS repeated-report-and-fingerprint\n");
} finally {
  await rm(fixtureRoot, { recursive: true, force: true });
}
