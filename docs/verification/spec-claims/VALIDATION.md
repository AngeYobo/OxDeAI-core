# Schema v2 migration validation

All changes remain uncommitted. The original architecture, AST selectors, evidence
capabilities, explicit required levels, CI command and vector boundary are
unchanged. [MIGRATION.md](MIGRATION.md) records the exact field migration and all
26 affected existing IDs, plus the three contextual locks added.

## Actual migration validation

| Command/check | Result |
|---|---|
| `pnpm verify:spec-claims` | Structural PASS: 29 records, comprising 26 requirements and 3 contextual locks; zero errors |
| `pnpm test:spec-claims` | 43/43 passed, zero skipped |
| `pnpm verify:spec-claims && pnpm test:spec-claims` | Existing CI command passed; two additional positive/schema tests were then added and the final 43-test suite passed separately |
| `pnpm typecheck` | Workspace PASS, including protocol builds |
| `pnpm -C packages/conformance validate` | 259 assertions passed |
| `pnpm test:vectors:all` | All constituent validators passed again; counts below |
| `node scripts/spec-claims/verify.mjs --json` | Parseable JSON; zero issues; all new metadata retained |
| `node scripts/spec-claims/verify.mjs --advisory` | 332 candidate prose lines / 594 unmapped static test names, unchanged; contextual locks do not suppress normative discovery |
| `node --check scripts/spec-claims/verify.mjs` | PASS |
| `node --check scripts/spec-claims/verify.test.mjs` | PASS |
| `git diff --check` | PASS |
| Migration-baseline registry comparison | All retained fields of all 26 existing records matched the pre-migration registry at migration time; post-#309 source citations were then reconciled separately without changing evidence or obligations |
| Protected surface diff | This spec-claims work changes no normative specification, protocol behavior or vector tree; source citations were reconciled against the already-merged #309 normative changes |

`pnpm test:vectors:all` executed `test:vectors:ts` (11), `test:vectors:auth`
(12), `test:vectors:pep` (9), `test:vectors:delegation` (12),
`test:vectors:trusted-time` (44 active/passed, zero failed/pending),
`test:vectors:go` and `test:vectors:py` (each 11 canonicalization + 8 Profile-C +
9 SignedKRL). These were actual validator executions, not inferred from references.
Subprocess self-tests and the vector aggregate used the previously necessary
sandbox escalation. No runtime suites were weakened or replaced. Core/guard test
counts in the historical section below are from the initial implementation, not
new runs for this schema-only migration.

## Test changes

The previous 25 tests remain, migrated to version 2. Eighteen tests were added:

- Ten CLI failure cases: legacy version, legacy status, dangling dependency,
  malformed inference guard, invalid decision flag, missing conditional context,
  three attempted lock promotions (obligation, source role, strength), and removal
  of required negatives from a deferred claim with a pending decision.
- Eight further cases: all 60 combinations of the three dimensions preserve
  evidence capabilities; all three locks pass without executable obligations;
  forward dependencies do not confer proof or resolution; all four RT-TRUST-2
  conditions remain represented; contextual excerpts do not suppress advisory
  discovery; malformed/duplicate dependency metadata fails; a lock may carry
  mapped evidence without gaining normative authority; contextual source drift
  and duplicate conditions fail structurally.

The initial six requested temporary failure demonstrations still run and pass.
No unresolved lock, dependency on one, conditional deployment prerequisite, or
pending maintainer decision causes CI failure. Invalid references and explicit
missing evidence obligations still fail; scope metadata cannot waive them.

## Review state

There are nine advisory pending maintainer decisions: the original six unmapped
requirements plus the three added contextual locks. CANON-ESC-001 has no discovered
repository definition; no escaping semantics were invented. RT-TRUST-1 remains a
state-provider residual. RT-TRUST-2 retains all four documented deployment closure
prerequisites, without asserting they are configured or sufficient for whole-system
trust. No normative ambiguity or lock was resolved.

Counts for the 26-record requirement inventory remain 20/26 implementation and
executable mappings, 12/12 required integration, 18/18 required negative, 18/25
security-critical with negative evidence, and 5/19 portable conformance mappings.
Post-#309 source-citation reconciliation did not change these evidence counts.
Locks are excluded from those coverage denominators. Structural PASS is not
semantic proof, whole-protocol conformance or maintainer approval.

---

# Original v1 implementation validation (historical)

This record describes actual local execution during implementation. It is not
read as evidence by the structural checker and is not an enduring attestation
for later commits. All changes were left uncommitted for maintainer review.

## Changes

Added:

- `scripts/spec-claims/verify.mjs`: schema checks, selectors, reports and advisory scan.
- `scripts/spec-claims/verify.test.mjs`: 25 tests including temporary CLI perturbations.
- `docs/verification/spec-claims/claims.json`: 26 curated claims.
- `docs/verification/spec-claims/README.md`: architecture, schema, corpus boundary,
  public-claim review, limitations and follow-up issues.
- `docs/verification/spec-claims/INVENTORY.md`: per-claim implementation/evidence audit snapshot.
- `docs/verification/spec-claims/VALIDATION.md`: this execution record.

Modified:

- `package.json`: `verify:spec-claims` and `test:spec-claims` commands.
- `.github/workflows/ci.yml`: one step in `build-test`, using the exact locally
  validated command `pnpm verify:spec-claims && pnpm test:spec-claims`.

No protocol source, normative document, vector, lockfile or existing test changed.

## Executed commands

| Exact command | Result |
|---|---|
| `pnpm verify:spec-claims` | PASS; 26 claims; no structural errors |
| `pnpm test:spec-claims` | 25/25 passed |
| `pnpm verify:spec-claims && pnpm test:spec-claims` | Exact new CI command passed after final checker edits |
| `pnpm typecheck` | PASS across workspace; includes `build:protocol` (core, SDK and guard builds) |
| `pnpm -C packages/core test` | 383/383 passed; core rebuilt |
| `pnpm -C packages/guard test` | 219/219 passed; guard test build passed |
| `pnpm -C packages/conformance validate` | 259 assertions passed; core and conformance builds passed |
| `pnpm test:vectors:all` | PASS; all constituent commands below executed successfully |
| `node scripts/spec-claims/verify.mjs --json` | PASS; parseable JSON, zero issues |
| `node scripts/spec-claims/verify.mjs --advisory` | PASS; 332 candidate prose lines and 594 static tests without registry mappings, advisory only |
| `node --check scripts/spec-claims/verify.mjs` | PASS |
| `node --check scripts/spec-claims/verify.test.mjs` | PASS |
| `git diff --check` | PASS |

Constituent commands actually executed by `pnpm test:vectors:all`:

| Command | Result |
|---|---|
| `pnpm test:vectors:ts` | 11 canonicalization vectors passed |
| `pnpm test:vectors:auth` | 12 authorization vectors passed |
| `pnpm test:vectors:pep` | 9 PEP vectors passed |
| `pnpm test:vectors:delegation` | 12 delegation vectors passed |
| `pnpm test:vectors:trusted-time` | 44 active, 44 passed, zero failed/pending |
| `pnpm test:vectors:go` | 11 canonicalization + 8 Profile-C + 9 SignedKRL passed |
| `pnpm test:vectors:py` | 11 canonicalization + 8 Profile-C + 9 SignedKRL passed |

Go and Python success is limited to these actual surfaces. No Rust run, complete
cross-language authorization/delegation/PEP verification, or live distributed
Redis deployment validation is claimed by this record.

Initial restricted-sandbox attempts could not capture Node subprocess output
(`spawnSync EPERM`) and could not create tsx's local IPC socket (`listen EPERM`).
The checker subprocess self-tests and the vector aggregate were rerun successfully
with approved sandbox escalation. Core/guard suites were also executed with that
permission so their subprocess/socket behavior was not suppressed. These retries
did not alter tests or replace evidence. Local Node was v23.3.0; CI uses Node 22.

## Verifier failure demonstrations

Each CLI mutation writes only a new temporary registry under the OS temporary
directory, invokes the checker, asserts exit status 1 and the diagnostic code,
then removes the temporary directory in `finally`. Normative sources are never
edited. All six specifically requested cases passed:

| Perturbation | Verified diagnostic |
|---|---|
| Duplicate claim ID | `DUPLICATE_ID` |
| Missing normative source | `MISSING_SOURCE` |
| Missing implementation file | `STALE_IMPLEMENTATION` |
| Missing evidence file | `STALE_EVIDENCE` |
| Required negative evidence removed | `MISSING_NEGATIVE` |
| Malformed claim | `MALFORMED` |

Additional passing tests cover stale test/vector IDs, symbols, source excerpts
and sections; missing integration/portable evidence; invalid classification;
TypeScript mislabeled cross-runtime; unknown fields; runner binding drift; path
traversal; absent implementation; malformed nested types; empty inventory;
comments/skips/dynamic names; isolated evidence removal; and visible
non-required gaps. The isolated repository fixture copies only referenced files
and confirms that replacing a test with a comment fails.

## Review outcome

- 20/26 claims have implementation and executable mappings.
- 12/12 required integration mappings and 18/18 required negative mappings resolve.
- 18/25 security-critical claims have negative evidence. Remaining cases are
  reported explicitly, including gaps/assumptions and selected positive properties.
- Five claims declare portable conformance evidence out of 19 portable semantic
  classifications; five other claims describe implementation-specific enforcement,
  and two describe deployment assumptions.
- Six claims remain unmapped: two evidence gaps, two normative ambiguities, two
  deployment assumptions. Their empty required levels are deliberate, visible
  inventory decisions, not claims that the requirements have been fulfilled.

The manual audit and recommended follow-up issues are in [README.md](README.md).
The per-claim selectors, runners and limits are in [INVENTORY.md](INVENTORY.md).
Structural PASS does not resolve the acknowledged normative ambiguities or make
claims of complete protocol conformance.
