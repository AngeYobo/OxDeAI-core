# OxDeAI Whitepaper Reconciliation TODO

This checklist tracks items that must be reconciled before the paper can be published externally.

## Structure

- [ ] Confirm there is only one Section 6.
- [ ] Confirm section numbering is continuous from 1 to 15.
- [ ] Confirm appendices are clearly marked as draft/reconciliation material.

## Repository reconciliation

- [ ] Verify all artifact field names against `@oxdeai/core`.
- [ ] Verify `AuthorizationV1` fields against the live type definitions.
- [ ] Verify `DelegationV1` fields against the live type definitions.
- [ ] Verify `SignedKRLV1` fields against the live type definitions.
- [ ] Verify canonicalization rules against `canonicalization-v1`.
- [ ] Verify all error code strings against implementation constants.
- [ ] Verify all conformance vector IDs against the live vector files.
- [ ] Verify all conformance assertion counts.
- [ ] Separate protocol conformance counts from implementation/unit/integration test counts.
- [ ] Verify all cited file paths.
- [ ] Verify cryptographic example signatures against the live vectors.
- [ ] Verify all references, including Meyman 2026, DOI, date, title, and license.

## Claim discipline

- [ ] Remove or downgrade any unsupported claim.
- [ ] Keep independent-security-review limitation explicit.
- [ ] Keep project-maintained implementation limitation explicit.
- [ ] Keep state-provider trust boundary explicit.
- [ ] Keep replay-store durability residual explicit.
- [ ] Keep KRL default-mode residual explicit.
- [ ] Keep the paper clearly separated from LGF/Frappe implementation notes.

## Publication readiness

- [ ] Remove reconciliation notes before publication.
- [ ] Remove all `[verify]` markers before publication.
- [ ] Produce a clean Markdown draft.
- [ ] Optionally produce a PDF draft after reconciliation.
