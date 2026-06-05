# Roadmap

**Last updated:** 2026-06-04

---

## Positioning

OxDeAI is an **execution authorization boundary** for autonomous and AI-native systems.

Core invariant:

> **No valid authorization → no execution path**

OxDeAI does not secure agents by trusting better agents. It secures execution by requiring verifiable authorization artifacts before side-effecting actions are allowed.

---

## Protocol Maturity

```text
implementation → interoperable protocol → executable interoperability → reviewer-ready protocol package
````

OxDeAI now specifies and validates:

* deterministic canonicalization
* `AuthorizationV1`
* `DelegationV1`
* `SignedKRLV1`
* PEP gateway enforcement
* external-provider interoperability profiles
* state-provider trust boundary requirements
* cross-language conformance across TypeScript, Go, and Python
* audit and standardization alignment documentation

Current maturity:

```text
interoperable protocol with executable cross-language conformance
```

OxDeAI is **not yet standard-adoption-ready**.

Remaining standardization gates include:

* independent security review
* external feedback / co-author channel
* release-policy decision for signed-required default migration
* continued external integration review

---

## Version Snapshot

> Verify exact package versions against `package.json` before release publication.

### Protocol / Core

- `@oxdeai/core`: 1.7.0
- `@oxdeai/conformance`: 1.5.0
- `@oxdeai/sdk`: 1.3.3

### Enforcement / Adapters

- `@oxdeai/guard`: 1.0.3
- `@oxdeai/sift`: 0.0.1
- `@oxdeai/langgraph`: 1.0.1
- `@oxdeai/openai-agents`: 1.0.1
- `@oxdeai/crewai`: 1.0.1
- `@oxdeai/autogen`: 1.0.1
- `@oxdeai/openclaw`: 1.0.1

### Tooling

- `@oxdeai/cli`: 0.2.4

### Compatibility

- `@oxdeai/compat`: 0.0.1

---

## Current State

### Validation

Current validation posture:

* build: pass
* tests: pass
* TypeScript conformance: 209 assertions
* Go harness: 28 assertions
* Python harness: 28 assertions
* aggregate conformance posture: 265 assertions across TypeScript, Go, and Python
* security gate: ALLOW
* API fingerprint: unchanged where required

### Cross-language coverage

Covered cross-language:

* canonicalization vectors
* SignedKRLV1 vectors
* Profile C state verification vectors
* Profile C Encoding B modes 006–008
* independent Ed25519 verification in Go and Python

### Boundary proof

```text
ALLOW
DENY_HASH_MISMATCH
REPLAY
BYPASS → rejected
```

### Core execution invariant

```text
proposal
→ authorization verification
→ PEP enforcement
→ execution only if allowed
```

If any verification step fails:

```text
DENY
→ no execution
```

---

## Architecture Doctrine

### Optimized for

* deterministic authorization: `(intent, state, policy) → ALLOW | DENY`
* fail-closed execution
* pre-execution enforcement
* non-bypassable PEP boundary
* portable offline verification
* proof-carrying authorization artifacts
* replay without re-reasoning
* explicit trust boundaries

### Not

* agent framework
* runtime replacement
* guardrail / output filtering system
* model-alignment system
* monitoring-only system
* sandboxing system
* policy-authoring product

---

# Milestones

---

## v1.1 - Authorization Artifact

**Status:** Done

Delivered:

* `AuthorizationV1`
* pre-execution gating semantics
* PEP verification contract
* fail-closed authorization model

Invariant:

```text
Only valid ALLOW artifacts may reach execution.
```

---

## v1.2 - Cryptographic Verification

**Status:** Done

Delivered:

* Ed25519 verification
* `alg` / `kid` / signature verification
* trusted keyset model
* signature failure conformance
* strict issuer / audience / expiry / replay checks

---

## v1.3 - Integration Surface

**Status:** Done

Delivered:

* SDK guard surface
* multi-framework demos
* deterministic envelope verification
* initial adapter model

---

## v1.4 - Ecosystem Adapter Layer

**Status:** Done

Delivered:

* unified PEP guard package
* adapter packages for major AI orchestration surfaces
* cross-adapter validation
* reproducible demo scenario

Adapters remain non-authoritative. They may propose actions. They do not define execution authority.

Invariant:

```text
proposal → authorization → execution
```

---

## v1.5 - Developer Experience

**Status:** Done

Delivered:

* quickstarts
* visual demos
* architecture docs
* reproducible integrations

Goal achieved:

> Run a demo in under 5 minutes.

---

## v2.0 - Delegated Authorization

**Status:** Done

Delivered:

* `DelegationV1`
* strict scope narrowing
* single-hop enforcement
* parent authorization binding
* local chain verification
* delegation replay protection
* conformance vectors
* cross-language verification

Invariant:

```text
Delegation may narrow authority.
Delegation may not expand authority.
```

---

## v2.5 - ETA Core / Interoperable Protocol Hardening

**Status:** Done

Goal:

> Turn OxDeAI from implementation into interoperable execution-time authorization protocol.

Delivered:

* canonicalization spec
* authorization spec
* delegation spec
* PEP gateway spec
* verification spec
* conformance vectors
* cross-language canonicalization
* cross-language Profile C verification
* cross-language SignedKRLV1 verification
* non-bypassable execution demo
* ETA alignment document
* protocol audit cleanup

### Interoperability hardening

Delivered:

* external provider wire encoding specification

  * Encoding A: Core-native
  * Encoding B: external-provider compatible
* external provider profiles

  * Profile A: Core-native `AuthorizationV1`
  * Profile B: external wire-compatible authorization
  * Profile C: full semantic state verification
* Profile C executable vectors
* Profile C Go/Python coverage for all 8 modes
* Encoding B modes 006–008 covered cross-language
* external provider threat model
* key custody and rotation guide
* replay-store TTL alignment guide
* state-provider trust boundary requirements

### Revocation hardening

Delivered:

* SignedKRLV1 verification path
* signed-required / signed-preferred / unsigned-legacy mode model
* persistent KRL high-watermark support
* last-known-good signed-KRL cache
* fail-closed KRL watermark persistence behavior
* migration warnings for unsigned legacy behavior

### Audit posture

Delivered:

* post-interoperability protocol audit
* ETA framework alignment
* RT-TRUST-1 specified with residual
* final audit readiness cleanup

Current audit posture:

```text
reviewer-ready, not standard-adoption-ready
```

---

## v2.6 - Project Readiness / External Engagement Surface

**Status:** In Progress

Goal:

> Make OxDeAI evaluable by external contributors, reviewers, integrators, and security researchers.

Scope:

* `GOVERNANCE.md`
* updated `CONTRIBUTING.md`
* `SECURITY.md`
* DCO contribution policy
* optional DCO enforcement workflow
* clear security disclosure path
* external integration proposal process
* no overclaiming of foundation, legal entity, or security-review status

Completion criteria:

* governance model reflects current project state
* security disclosure path exists
* contribution process is clear
* DCO requirement documented
* no unsupported legal or standardization claims
* no protocol/runtime changes

---

## v2.7 - Independent Security Review Scoping

**Status:** Planned

Goal:

> Prepare OxDeAI for independent security review.

Scope:

* define review surface
* define out-of-scope areas
* prepare reviewer package
* map artifacts to audit sections
* define threat model focus
* define expected deliverables
* define success criteria
* identify reviewer profile

Review surface should include:

* `AuthorizationV1`
* `DelegationV1`
* `SignedKRLV1`
* canonicalization-v1
* PEP gateway boundary
* OxDeAIGuard
* Profile A/B/C
* KRL high-watermark / LKG cache
* state-provider trust boundary
* conformance vectors and harnesses
* audit and ETA alignment documents

Completion criteria:

* security review issue opened
* review package defined
* candidate reviewers identified
* cost / timeline understood
* funding or sponsor path clarified

---

## v2.8 - External Feedback / Co-author Channel

**Status:** Planned

Goal:

> Create a structured path for external technical feedback.

Scope:

* external feedback process
* integration proposal template
* reviewer/adopter feedback template
* possible RFC-lite process
* public discussion conventions
* issue labels and triage model

Constraints:

* do not create fake foundation governance
* do not create formal standards-body claims
* do not give external integrators protocol authority
* preserve maintainer decision model until real contributor base exists

Completion criteria:

* external feedback path documented
* integration proposal process stable
* public contribution route clear
* at least one external technical review or integration proposal processed under the model

---

## v3.0 - Release-Policy Gate for Signed-Required Default

**Status:** Planned / Release-Gated

Goal:

> Decide when `signed_required` becomes the default KRL posture and when `unsigned_legacy` is removed.

Scope:

* semver / release policy
* migration notice
* changelog
* deprecation timeline
* pre-release or major-release decision
* user migration guide
* default flip to `signed_required`
* eventual `unsigned_legacy` removal

Constraints:

* do not flip defaults without release-boundary decision
* do not remove unsigned legacy without migration window
* do not overstate signed-required coverage for deployments that do not configure it

Related:

* #116
* SignedKRLV1
* KRL high-watermark
* LKG cache

---

## v3.x - Infra Integrations

**Status:** Planned

Goal:

> Make OxDeAI a drop-in execution boundary for infrastructure systems.

Scope:

* HTTP PEP package
* Express / Fastify middleware
* route-level enforcement
* service-to-service authorization examples
* production deployment checklist
* network isolation guidance

Example:

```text
POST /payments/charge
→ verify AuthorizationV1
→ execute or deny
```

Constraint:

```text
PEP must remain outside the agent runtime.
```

---

## v4.x - Verifiable Execution Evidence

**Status:** Planned

Goal:

> Extend OxDeAI from authorization enforcement to verifiable execution evidence.

Scope:

* execution receipts
* `VerificationEnvelopeV1`
* Merkle batching
* proof-of-inclusion
* optional on-chain anchoring
* audit evidence export

Constraint:

```text
authorization remains off-chain-first
```

---

# Current Priorities

## Done

* authorization artifacts
* cryptographic verification
* canonicalization-v1
* PEP gateway specification
* delegated authorization
* adapter surface
* external provider interoperability hardening
* Profile A/B/C specification
* Profile C cross-language coverage
* SignedKRLV1 coverage
* persistent KRL watermark
* last-known-good KRL cache
* state-provider requirements spec
* ETA alignment document
* final protocol audit cleanup

## In Progress

* governance / contribution / security disclosure docs
* project-readiness surface for external reviewers

## Next

* independent security review scoping
* external feedback / co-author channel
* release-policy decision for signed-required default migration

## Planned Later

* HTTP PEP integrations
* production deployment checklist
* structured decision event schema
* verifiable execution receipts
* optional evidence anchoring

---

# Documentation Map

## Core Specifications

* `docs/spec/core/canonicalization-v1.md`
* `docs/spec/core/authorization-v1.md`
* `docs/spec/core/delegation-v1.md`
* `docs/spec/artifacts/signed-krl-v1.md`
* `docs/spec/enforcement/pep-gateway-v1.md`
* `docs/spec/verification-v1.md`

## Interoperability

* `docs/spec/interoperability/external-provider-profile.md`
* `docs/spec/state-provider-requirements.md`

## Audit and Standardization

* `docs/audits/protocol-audit-post-interoperability.md`
* `docs/standardization/execution-time-authorization-alignment.md`

## Operations and Security

* `docs/spec/replay-store-ttl-alignment.md`
* `docs/spec/threat-model-external-providers.md`
* `docs/spec/key-custody-and-rotation.md`
* `SECURITY.md`

## Governance and Contribution

* `GOVERNANCE.md`
* `CONTRIBUTING.md`

---

# Key Insight

```text
Agents generate actions.
OxDeAI decides whether they are authorized.
The PEP enforces the boundary.
```