# Registry schema migration: v1 → v2

This is an explicit curated migration, not a runtime repair path. Version 1 and its overloaded `status` are rejected by the version 2 checker. At the migration baseline, all 26 previous IDs, titles, source paths/headings/excerpts, strengths, categories, notes, implementation/evidence records, classifications and explicit evidence obligations were preserved, with `source.role=normative` added to existing sources. After normative spec update #309, selected source headings/excerpts were reconciled to the updated specification text without changing their evidence mappings or executable obligations.

The new schema keeps independently reviewed normative, evidence and scope dimensions. No state or dependency automatically creates, suppresses or satisfies executable obligations.

| v1 status | normativeState | evidenceState | scopeDisposition | maintainerDecisionRequired |
|---|---|---|---|---|
| mapped | specified | mapped | in-scope | false |
| gap | specified | gap | in-scope | true |
| ambiguous | ambiguous | gap | in-scope | true |
| assumption | specified | gap | deployment | true |

Other additions: `recordType`, `appliesWhen`, `dependsOn`, `inferenceGuard`. Existing requirements have `recordType=requirement` and `appliesWhen=[]`. All records explicitly prohibit STRUCTURAL_PASS → SEMANTIC_PROOF and TESTED → WHOLE_PROTOCOL_CONFORMANCE. IDs now accept one or more terminal digits, preserving RT-TRUST-1 and RT-TRUST-2 verbatim.

| Existing affected ID | Former status | New normative / evidence / scope | Added dependencies |
|---|---|---|---|
| CANON-001 | mapped | specified / mapped / in-scope | None |
| CANON-002 | mapped | specified / mapped / in-scope | None |
| CANON-003 | gap | specified / gap / in-scope | None |
| AUTH-ARTIFACT-001 | mapped | specified / mapped / in-scope | None |
| AUTH-VERIFY-001 | mapped | specified / mapped / in-scope | None |
| AUTH-VERIFY-002 | mapped | specified / mapped / in-scope | None |
| AUTH-VERIFY-003 | mapped | specified / mapped / in-scope | None |
| AUTH-BIND-001 | mapped | specified / mapped / in-scope | None |
| AUTH-TIME-001 | mapped | specified / mapped / in-scope | None |
| AUTH-TRUST-001 | mapped | specified / mapped / in-scope | None |
| AUTH-REPLAY-001 | mapped | specified / mapped / in-scope | None |
| TRUSTED-TIME-001 | mapped | specified / mapped / in-scope | None |
| TRUSTED-TIME-002 | mapped | specified / mapped / in-scope | None |
| DELEGATION-001 | mapped | specified / mapped / in-scope | None |
| DELEGATION-002 | mapped | specified / mapped / in-scope | None |
| DELEGATION-003 | mapped | specified / mapped / in-scope | None |
| SIGNED-KRL-001 | mapped | specified / mapped / in-scope | RT-TRUST-2 |
| SIGNED-KRL-002 | mapped | specified / mapped / in-scope | RT-TRUST-2 |
| PROFILE-C-001 | mapped | specified / mapped / in-scope | RT-TRUST-1 |
| PEP-ENFORCE-001 | mapped | specified / mapped / in-scope | None |
| PEP-DEPLOY-001 | assumption | specified / gap / deployment | None |
| STATE-TRUST-001 | assumption | specified / gap / deployment | RT-TRUST-1 |
| VERIFY-ORDER-001 | ambiguous | ambiguous / gap / in-scope | None |
| DELEGATION-AUDIT-001 | gap | specified / gap / in-scope | None |
| ETA-SIGNING-001 | ambiguous | ambiguous / gap / in-scope | None |
| ETA-DETERMINISM-001 | mapped | specified / mapped / in-scope | None |

One-time migration-baseline comparison: all retained fields of all 26 records matched the pre-migration registry. After #309, source citations for CANON-002, SIGNED-KRL-001 and SIGNED-KRL-002 were updated to their current normative text, and the contextual citation for CANON-ESC-001 was refreshed. No evidence mapping, normative strength, classification or required level was changed by that reconciliation.

| Added lock | Normative / evidence / scope | Source role | Executable obligations |
|---|---|---|---|
| CANON-ESC-001 | unresolved / unassessed / deferred | context | None |
| RT-TRUST-1 | non-normative / unassessed / deployment | context | None |
| RT-TRUST-2 | non-normative / unassessed / conditional | context | None |

All three locks require maintainer decisions. CANON-ESC-001 has no discovered repository definition and remains unresolved. RT-TRUST-1 is an audit residual, not a duplicate of STATE-TRUST-001. RT-TRUST-2 records a conditional closure context, not closure or satisfaction of configuration. The contextual source role prevents promotion of these records into normative obligations.

Specific forbidden inferences are also recorded for PROFILE-C-001 and STATE-TRUST-001 (state-hash match → trusted state source) and SIGNED-KRL-001/002 (valid signature → closed deployment residual). Dependencies are informational links, not evidence inheritance.

Modified for this migration: claims.json, verify.mjs, verify.test.mjs, README.md, INVENTORY.md and VALIDATION.md. Added: this MIGRATION.md. Root commands and CI wiring remain as in the original uncommitted implementation.

See [VALIDATION.md](VALIDATION.md) for migration validation results.
