# Security Gate Decision Artifact

Release evidence for the freshness-dependent security advisory gate. This is
not an OxDeAI runtime authorization artifact, not `ExecutionReceiptV1`, and
not post-execution evidence; it is a release-evidence record binding one
advisory observation to the exact freeze candidate and dependency graph it
was evaluated against.

The advisory result itself is not deterministic: the external advisory
database and observation time are mutable inputs, so the same commit and
lockfile can produce a different decision on a later run. What IS
reproducible is the hashing: identical retained inputs recompute to identical
hashes, so a reviewer can verify the artifact was not altered after the fact.

## Format (formatVersion 2)
```json
{
  "formatVersion": 2,
  "type": "SecurityGateDecision",
  "decision": "ALLOW",
  "reason": "no blocking findings",
  "timestamp": "2026-04-02T10:00:00.000Z",
  "candidateSha": "a69f5cee8fb99a46ceff8df6f6b29b1002275335",
  "lockfileHash": "45b6a7d0f6f5dc590490b9db710c1cef4ec6b71f11593751ba3e8b3832a299df",
  "advisorySource": "pnpm audit --json (pnpm 9.12.0)",
  "policyHash": "...",
  "exceptionsHash": "...",
  "findingsHash": "...",
  "inputHash": "...",
  "artifactHash": "..."
}
```

`formatVersion: 1` artifacts (no `candidateSha`/`lockfileHash`/`advisorySource`)
remain valid for their own hash verification; `verify-security-gate-artifact.mjs`
hashes whatever fields the artifact actually has, so it accepts both versions.

Hashes are SHA-256 over a canonical (sorted-key) JSON representation:
- `policyHash`: hash of `policy.rules`
- `exceptionsHash`: hash of `exceptions`
- `findingsHash`: hash of normalized findings
- `inputHash`: hash of `{ policyHash, exceptionsHash, findingsHash, decision, reason }`. Scope unchanged from formatVersion 1: this is the advisory-decision commitment, independent of which candidate/lockfile produced it.
- `artifactHash`: hash of the full artifact object (including `candidateSha`, `lockfileHash`, `advisorySource`) without the `artifactHash` field itself. Changing any bound provenance field changes `artifactHash`.

## Provenance fields

- `candidateSha`: the exact Git commit SHA evaluated. Never a branch name or
  other mutable ref. Defaults to `git rev-parse --verify HEAD`; pin explicitly
  with `--candidate-sha=<sha>` for release/freeze tooling that must not depend
  on ambient mutable Git state (for example, generating evidence for `S_freeze`
  against a specific commit regardless of what branch happens to be checked
  out). Malformed or undeterminable values fail evidence generation; they are
  never silently omitted or guessed.
- `lockfileHash`: SHA-256 of the exact `pnpm-lock.yaml` bytes evaluated.
  Defaults to the repo-root lockfile; pin explicitly with `--lockfile=<path>`.
  Also fails generation if the file cannot be read.
- `advisorySource`: identifies the audit tool/command that produced the raw
  advisory input (for example `pnpm audit --json (pnpm 9.12.0)`). Best-effort
  when auto-detected; override with `--advisory-source=<text>` when the
  environment generating the artifact differs from the one that produced the
  audit input. This does not claim the advisory database is immutable, only
  which tool produced the observation.

## Raw advisory input

The raw `pnpm audit --json` output used by the gate is retained alongside the
decision artifact (same directory, `audit.json`), not just committed to via
`findingsHash`. A hash without the underlying findings is a commitment, not
review evidence.

## What it proves
- The decision (ALLOW/DENY) for a specific, retained set of inputs.
- Integrity of those inputs: policy rules, exceptions, raw findings.
- Which exact commit and lockfile the observation is bound to.
- Reproducible hash verification: recomputing the hashes from the retained
  inputs matches the stored values if the artifact has not been altered.

## What it does NOT prove
- No cryptographic signature or key-based trust model.
- No guarantee of who produced the artifact.
- No claim that the advisory database is immutable or that the same commit
  will produce the same decision on a later run.
- Not an OxDeAI runtime authorization artifact, `ExecutionReceiptV1`, or
  post-execution evidence.

## Generate

Ad hoc (auto-derives candidateSha from HEAD, lockfileHash from the repo-root
lockfile, advisorySource from the local pnpm version):
```
node scripts/security-gate.mjs audit.json security/vuln-policy.json --artifact-out=security-gate-decision.json
```

Release evidence for a specific freeze candidate:
```
node scripts/security-gate.mjs audit.json security/vuln-policy.json \
  --artifact-out=security-evidence/security-gate-decision.json \
  --candidate-sha=<freeze-candidate-sha>
```

Full evidence-capture path (writes `security-evidence/audit.json` and
`security-evidence/security-gate-decision.json`, fails if provenance cannot
be determined):
```
pnpm run security:evidence
```

`security-evidence/` is gitignored: generated evidence is not committed
automatically. Committing a specific frozen snapshot is a deliberate,
separate decision, not something these scripts do on their own.

## Verify
```
node scripts/verify-security-gate-artifact.mjs security-gate-decision.json
```

Expected output: PASS/FAIL with computed vs stored hash. If the hash matches,
the artifact is intact for the given content. This confirms integrity of the
retained artifact; it does not re-run the audit or re-evaluate policy.
