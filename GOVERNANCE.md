# OxDeAI Governance

**Status:** Working governance model for OxDeAI v1  
**Last updated:** 2026-06-04

This document describes how OxDeAI is governed: who decides what, how decisions are made, and how the project relates to contributors, adopters, security reviewers, and the broader execution-time authorization community.

OxDeAI is still early. This governance model reflects the project’s current state honestly: solo-maintained, Apache-2.0 licensed, no foundation governance yet, and no independent security review completed yet. The model may evolve as the project grows, but the project’s governing discipline is stable:

- discovery before implementation
- decisions pinned upstream in specs or audit documents
- conformance-driven claims
- conservative documentationf
- named residual risks

---

## 1. Project Stewardship

OxDeAI is currently maintained by **Ange Yobo** as the original author and lead architect.

The project is open-source under the Apache License 2.0.

A separate legal vehicle for OxDeAI may be established in the future. Until then, copyright is held by the respective authors and licensed under Apache 2.0.

OxDeAI is maintained as a separate open-source project from Oxalio Labs. Oxalio Labs is a separate fintech infrastructure company where the author serves in a different role. Any future commercial relationship, sponsorship, or shared infrastructure would be disclosed.

OxDeAI is not currently governed by a foundation, standards body, steering committee, or formal multi-maintainer council.

---

## 2. Scope of Governance

This governance document covers decisions about:

- OxDeAI protocol specifications
- `AuthorizationV1`
- `DelegationV1`
- `SignedKRLV1`
- `canonicalization-v1`
- state-provider trust boundary requirements
- PEP gateway behavior
- conformance vectors
- cross-language harnesses
- reference implementation packages
- audit and standardization documentation
- project contribution process
- project security disclosure process
- project naming, licensing, and IP discipline

This document does not govern:

- independent third-party implementations
- private deployments
- forks that intentionally diverge from the canonical repository
- commercial services built on top of OxDeAI
- unrelated projects maintained by the same author

---

## 3. Decision Model

### 3.1 Current model: BDFL with documented discipline

OxDeAI currently uses a **BDFL with documented discipline** model.

The lead architect makes final decisions on protocol design, specification changes, conformance scope, and contribution acceptance.

This is appropriate for the project’s current stage: early, technically coherent, and still primarily maintained by the original author.

However, decisions are constrained by the project’s documented discipline:

### Discovery before implementation

Substantial protocol, security, or conformance changes should begin with discovery.

Discovery means reading the affected specs, implementation, tests, vectors, and audit entries before changing behavior.

### Decisions pinned upstream

Protocol decisions should be captured in the relevant specification, audit entry, or issue before implementation.

Implementation should not silently redefine protocol semantics.

### Conformance-driven claims

OxDeAI should only claim behavior as portable or externally verifiable when there are corresponding specs, vectors, tests, or cross-language harnesses.

Claims must be tied to evidence.

### Conservative documentation

OxDeAI documentation should avoid marketing-style overclaiming.

If something is partial, deployment-dependent, not independently reviewed, or not yet standardized, the documentation should say so.

### Residuals named

Known risks must remain visible in the audit and related specifications.

Residual risks should not be hidden behind vague language.

---

## 4. Decision Categories

Different decisions require different levels of review.

### 4.1 Protocol semantic changes

Examples:

- changes to `AuthorizationV1`
- changes to `DelegationV1`
- changes to `SignedKRLV1`
- changes to `canonicalization-v1`
- changes to fail-closed semantics
- changes to PEP enforcement behavior

These require:

- an issue
- discovery or design notes
- spec updates
- conformance vector updates where applicable
- audit updates
- validation before merge

Protocol semantic changes should be rare and deliberate.

### 4.2 Conformance vector changes

Conformance vectors define portable behavior.

New vectors are welcome when they strengthen external verifiability.

Changing expected outcomes in existing vectors is treated as a protocol semantic change unless the existing vector is demonstrably wrong.

### 4.3 Cross-language harness changes

Cross-language harnesses should independently verify protocol behavior.

They must not depend on the TypeScript reference implementation at runtime.

New harnesses should prioritize:

- independent canonicalization
- independent hash verification
- independent Ed25519 verification
- exact vector compatibility
- clear failure output

### 4.4 Documentation and audit changes

Documentation changes are encouraged, but must preserve the project’s conservative claim discipline.

Audit updates should be internally consistent across all affected sections.

If a P-item or residual changes state, update every affected reference in the audit, not only the primary follow-up section.

### 4.5 External integration proposals

External integrations are reviewed against the core OxDeAI boundary:

```text
routing proposes
authorization decides
PEP enforces
````

External metadata may explain, audit, or contextualize routing and agent behavior, but it must not define, expand, reduce, or modify execution authority.

The non-authoritative metadata pattern established through external integration review is the preferred model for third-party routing or audit evidence.

---

## 5. Future Governance Evolution

The current model may evolve as the project gains contributors, adopters, and independent reviewers.

Possible future stages include:

### Maintainer expansion

If additional contributors demonstrate sustained technical judgment and alignment with the project’s discipline, they may be added as maintainers.

Maintainer authority would be based on contribution quality, protocol understanding, and adherence to the documented process.

### Core team

If multiple maintainers become active, OxDeAI may move to a small core-team model.

The core team would govern the canonical repository and approve protocol-level changes.

### Advisory or review group

If OxDeAI gains external adoption, an advisory group of independent technical reviewers, adopters, and security experts may be created.

Such a group would advise on protocol direction, security posture, and standardization readiness.

### Foundation or neutral stewardship

If OxDeAI becomes broadly adopted, transfer to a neutral foundation may be considered.

No foundation transfer is currently in place.

Any such change would be proposed publicly and reflected in this document before taking effect.

---

## 6. Communication Channels

Primary project communication happens through GitHub:

* issues for bugs, proposals, and design discussion
* pull requests for reviewable changes
* discussions if enabled for broader topics

General contact:

```text
contact@oxdeai.dev
```

Security contact:

```text
security@oxdeai.dev
```

Security issues should not be reported as public GitHub issues. See `SECURITY.md`.

---

## 7. Intellectual Property and Licensing

### 7.1 License

OxDeAI is licensed under the Apache License 2.0.

The license applies to code, documentation, conformance vectors, and specifications unless a file states otherwise.

### 7.2 Contributor rights

Contributors retain copyright in their contributions.

By contributing, they license their contributions under Apache 2.0.

OxDeAI does not currently require copyright assignment.

### 7.3 DCO

OxDeAI uses Developer Certificate of Origin sign-off for contributions.

The contribution process is described in `CONTRIBUTING.md`.

### 7.4 IP discipline

OxDeAI uses its own component names and protocol terminology, including:

* `AuthorizationV1`
* `DelegationV1`
* `SignedKRLV1`
* `OxDeAIGuard`
* `canonicalization-v1`

The project should avoid adopting names from external patent-encumbered systems as OxDeAI component names.

External frameworks may be cited where relevant, with proper attribution and without implying affiliation or derivation.

The independent-development statement in `docs/standardization/execution-time-authorization-alignment.md` should be preserved unless it becomes factually inaccurate.

---

## 8. Security Governance

OxDeAI has not yet undergone independent security review.

The current security posture is documented in:

```text
docs/audits/protocol-audit-post-interoperability.md
```

Known residuals include, but are not limited to:

* RT-TRUST-1: state provider integrity, specified with residual deployment responsibility
* RT-TRUST-2: KRL transport / migration-tracked revocation integrity posture
* RT-TRUST-3: replay store bootstrapping and deployment residuals

Security disclosures should be sent privately to:

```text
security@oxdeai.dev
```

The disclosure process is defined in `SECURITY.md`.

---

## 9. External Engagement

OxDeAI welcomes external feedback, implementation experience, and integration proposals.

External engagement may include:

* issue discussions
* pull requests
* conformance vector proposals
* independent implementation reports
* security review feedback
* academic or standards-oriented review
* integration proposals from other systems

External feedback is valued, especially when tied to concrete implementation or deployment experience.

External feedback does not create formal voting rights under the current governance model.

### External integrator engagement

OxDeAI has engaged with external integrators on technical grounds during its development.

The most substantial engagement to date has been with Sift / Walko Systems, which produced the `@oxdeai/sift` adapter package and surfaced several protocol-level alignment issues that were resolved at the specification layer.

Issue #122 documents an ongoing engagement around non-authoritative routing/audit metadata patterns.

These engagements are purely technical. OxDeAI has not received funding, sponsorship, advisory compensation, or other commercial benefit from any external integrator. No external integrator has decision authority over OxDeAI's protocol design.

If a commercial relationship with any external integrator is established in the future, it will be disclosed in this document.

---

## 10. Integration Proposal Process

External integration proposals should be opened as GitHub issues.

A good integration proposal should describe:

* the external system
* the proposed integration point
* whether the integration is authoritative or non-authoritative
* what data is exchanged
* how canonicalization is handled
* how authorization boundaries are preserved
* how failure modes behave
* what test vectors or examples exist

The default review rule is:

```text
external systems may propose or explain
AuthorizationV1 decides
PEP enforces
```

Integrations that attempt to influence `AuthorizationV1` verification or PEP enforcement without going through the documented authority path will not be accepted.
The project may accept integration requests that produce protocol-level improvements applicable to all integrators, such as wire-format alignment, canonicalization clarification, or portable conformance coverage.

The project will not accept integration requests that couple OxDeAI protocol semantics to a specific integrator's needs, even when the request is technically reasonable.

---

## 11. Conflict of Interest

The lead maintainer may have roles in other companies or projects.

OxDeAI is maintained as a separate open-source protocol project.

If a future commercial relationship, sponsorship, paid support arrangement, shared infrastructure, or other material relationship could affect OxDeAI governance, it should be disclosed.

Project decisions should be made in the interest of OxDeAI’s protocol integrity, not in the interest of another commercial entity.

---

## 12. Changing This Governance Document

Changes to this document must be proposed through pull requests.

Minor edits may include:

* wording clarifications
* contact updates
* link updates
* formatting fixes

Substantive edits include changes to:

* decision model
* stewardship
* licensing posture
* IP discipline
* security disclosure posture
* external engagement process

Substantive edits should be discussed publicly before merge.

---

## 13. Current Governance Summary

Current state:

* solo-maintained / lead-architect governed
* Apache-2.0 licensed
* BDFL with documented discipline
* no foundation governance yet
* no maintainer committee yet
* no independent security review yet
* external engagement beginning
* protocol decisions constrained by specs, audit, vectors, and fail-closed invariants

OxDeAI’s governance is intentionally conservative.

The project should prefer being precise and externally reviewable over appearing more mature than it is.


