# Security Authorization Gate

## Status

Non-normative (developer documentation)






Repo-level pre-merge security checks (non-normative). Protocol definitions live in `SPEC.md` and `docs/spec/`; these checks enforce repository policy, not OxDeAI protocol artifacts.

Two independent CI checks, both required for release:

- **Security Policy Boundary**: reproducible release check. Runs the repo-local policy-boundary repro harness (`pnpm run security:policy-boundary`). Depends only on repo state and inputs; a given commit produces the same result on every rerun.
- **Security Advisory Gate**: freshness-dependent security evidence. Evaluates the generated `pnpm audit` output against `security/vuln-policy.json` and the current exception list. The external advisory database can change while the commit and lockfile stay the same, so this check can pass or fail differently across reruns of an unchanged commit.

The advisory gate never invokes the policy-boundary harness, and the harness never depends on advisory data. Neither check's failure is treated as a warning; both block merge on failure.

## Core invariant

No valid exception -> no merge path.

This gate is intentionally fail-closed.

High and critical findings always block. Moderate findings block unless covered by a valid, non-expired exception.
High and critical severities are always denied, regardless of policy rules.

## Policy-as-code

`security/vuln-policy.json`
```json
{
  "rules": {
    "critical": "deny",
    "high": "deny",
    "moderate": "require_exception",
    "low": "warn"
  },
  "exceptions": [
    {
      "id": "GHSA-xxxx",
      "package": "pkg-name",
      "severity": "moderate",
      "reason": "why this is temporarily accepted",
      "expires_on": "2026-06-30"
    }
  ]
}
```

Semantics:
- intent: merge this repo state
- state: audit findings + exception state + current date
- policy: severity rules + exception requirements
- decision: ALLOW / DENY

Rules:
- Every exception must include `reason`, `severity`, and `expires_on` (ISO date).
- Expired exceptions fail the gate.
- Critical/high: deny.
- Moderate: require a valid, non-expired exception.
- Low: warn (does not block).

## Adding a temporary exception
1) Add to `security/vuln-policy.json` with id/package/severity, a short reason, and a near-term `expires_on`.
2) Commit the change and re-run the gate.
3) Remove exceptions once fixed.

## How the advisory gate runs
- CI runs `pnpm audit --json > audit.json || true`
- Then `node scripts/security-gate.mjs audit.json security/vuln-policy.json`
- The gate prints blocking findings, matched/expired exceptions, warnings, and the final decision (ALLOW / DENY). It does not run the policy-boundary harness; that runs as the separate `Security Policy Boundary` CI check (`pnpm run security:policy-boundary`).
