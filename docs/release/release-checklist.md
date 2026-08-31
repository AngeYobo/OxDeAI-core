# OxDeAI Package Release Checklist

## Status

Normative release checklist.

Use this checklist with `docs/release/RELEASE.md` and `docs/release/RELEASING.md`.

OxDeAI uses package-scoped versions and package-scoped tags. Do not create global `vX.Y.Z` tags for normal package releases.

## 1. Identify Release Scope

List every package being released:

```text
package name:
package path:
current package.json version:
new package.json version:
release tag:
changelog path:
npm package:
```

The release tag must be package-scoped:

```text
core-vX.Y.Z
sdk-vX.Y.Z
conformance-vX.Y.Z
guard-vX.Y.Z
cli-vX.Y.Z
langgraph-vX.Y.Z
crewai-vX.Y.Z
autogen-vX.Y.Z
openai-agents-vX.Y.Z
openclaw-vX.Y.Z
```

For coordinated releases, repeat the mapping for every package. Multiple tags may point to the same commit, but package versions remain independent.

## 2. Preflight

```bash
git fetch origin --tags --prune
git status -sb
pnpm tags:audit
pnpm release:preflight --package <package-short-name>
npm whoami
gh auth status
```

The working tree must be clean before tagging or publishing.

Run the npm-aware preflight immediately before publication:

```bash
pnpm release:preflight --package <package-short-name> --check-npm
```

The preflight fails closed on ambiguous package names, tag mismatches, existing tags, missing changelog entries, dirty worktrees, and npm version conflicts.

Check current npm versions:

```bash
npm view @oxdeai/core version --registry=https://registry.npmjs.org
npm view @oxdeai/sdk version --registry=https://registry.npmjs.org
npm view @oxdeai/conformance version --registry=https://registry.npmjs.org
npm view @oxdeai/guard version --registry=https://registry.npmjs.org
npm view @oxdeai/cli version --registry=https://registry.npmjs.org
```

## 3. Version and Changelog

For each released package:

1. Bump only that package's `package.json` version.
2. Refresh `pnpm-lock.yaml` if the version bump changes the lockfile.
3. Update that package's changelog.
4. Include security, breaking-change, migration, and compatibility notes where applicable.

Do not infer a shared version line from a coordinated release commit.

## 4. Baselines and Vectors

For `@oxdeai/core` API changes:

```bash
pnpm -C packages/core api:report
pnpm -C packages/core api:fingerprint
pnpm -C packages/core api:check
pnpm -C packages/core api:fingerprint:check
```

If API drift is intentional, review and update the committed baseline files. Do not commit generated temp output unless the package's API process explicitly requires it.

For conformance vector changes:

```bash
pnpm -C packages/conformance extract
pnpm -C packages/conformance validate
```

Vector changes must be intentional and documented in the relevant changelog or release notes.

## 5. Required Gates

Repository-wide gates:

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm test
```

Package-specific gates:

```bash
pnpm -C packages/core api:check
pnpm -C packages/core api:fingerprint:check
pnpm -C packages/conformance validate
pnpm -C packages/guard test
```

Run only the package-specific gates that apply to the packages being released, plus any affected smoke tests.

All required gates must pass before tag creation and npm publication.

## 6. Optional CLI Smoke

Run this when releasing `@oxdeai/cli` or when changes affect envelope generation/verification:

```bash
pnpm -C packages/cli start -- init --file /tmp/oxdeai-policy.json --json
pnpm -C packages/cli start -- launch PROVISION 320 us-east-1 --agent agent-1 --nonce 1 --json
pnpm -C packages/cli start -- build --state .oxdeai/state.json --out .oxdeai/snapshot.bin --json
pnpm -C packages/cli start -- make-envelope --out .oxdeai/envelope.bin --json
pnpm -C packages/cli start -- verify --kind snapshot --file .oxdeai/snapshot.bin --json
pnpm -C packages/cli start -- verify --kind audit --file .oxdeai/audit.ndjson --mode strict --json
pnpm -C packages/cli start -- verify --kind envelope --file .oxdeai/envelope.bin --mode strict --json
```

Strict mode may return `inconclusive` without `STATE_CHECKPOINT`; record that result if it occurs.

## 7. Commit and Tag

Commit release changes first:

```bash
git diff --stat
git add <changed package.json files> <changed changelog files> pnpm-lock.yaml
git commit -m "chore(release): <package> vX.Y.Z"
```

Create package-scoped tags only:

```bash
git tag -a core-vX.Y.Z -m "core vX.Y.Z"
```

For coordinated releases:

```bash
git tag -a core-vX.Y.Z -m "core vX.Y.Z"
git tag -a sdk-vA.B.C -m "sdk vA.B.C"
git tag -a conformance-vD.E.F -m "conformance vD.E.F"
```

Push:

```bash
git push origin main
git push origin core-vX.Y.Z
```

For coordinated releases, push all package tags explicitly.

## 8. Pack and Publish

For each released package:

```bash
git show --no-patch --decorate <package-tag>
pnpm -C <package-path> pack --pack-destination /tmp
pnpm -C <package-path> publish --access public --registry=https://registry.npmjs.org
```

The npm package version must match the package's `package.json` version and package-scoped Git tag.

## 9. Post-Publish Verification

For each released package:

```bash
npm view <package-name> version --registry=https://registry.npmjs.org
npm view <package-name>@<version> dist.tarball --registry=https://registry.npmjs.org
git show --no-patch --decorate <package-tag>
```

Create or verify the GitHub release:

```bash
gh release view <package-tag>
```

If it does not exist:

```bash
gh release create <package-tag> --title "<package> vX.Y.Z" --notes-file <notes-file>
```

## 10. Release Artifact Mapping

Record this mapping in the release notes or release issue:

| Field | Value |
|---|---|
| package | |
| package path | |
| package.json version | |
| Git tag | |
| Git commit | |
| changelog entry | |
| npm package/version | |
| npm tarball URL | |
| GitHub release URL | |
| validation commands | |

For coordinated releases, include one row per package.

## 11. Failure Recovery

If tag creation fails, fix locally before pushing.

If a tag was pushed but npm publish failed, do not move the tag. Publish from the tagged commit if package contents are unchanged. If contents must change, create a new package version and tag.

If npm publish succeeded but GitHub release creation failed, create the GitHub release for the already published package tag.

If a bad npm package was published, ship a new corrective version. Do not reuse the original version or move the original tag.

## 12. Security Check

Before publishing, confirm:

- no secrets, OTPs, private keys, or production signing material are committed
- test keys are clearly test-only
- security-relevant changes are called out in changelog and GitHub release notes
- disclosure-sensitive details follow `docs/security/SECURITY.md`
