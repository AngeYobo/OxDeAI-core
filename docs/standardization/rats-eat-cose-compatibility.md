# OxDeAI Compatibility Analysis with RATS / EAT / COSE

**Document type:** Standardization positioning artifact
**Status:** Working Draft — no compatibility decisions taken
**Scope:** Compatibility analysis only — no protocol changes, no code changes, no conformance vector changes
**Gating relationship:** This document MUST reach a decided state before `ExecutionReceiptV1` is frozen.
**Related documents:** `docs/standardization/aarm-alignment.md`, `docs/spec/core/canonicalization-v1.md`, `docs/spec/artifacts/authorization-v1.md`

---

## 1. Purpose and Scope

This document is intended to record an explicit decision, per surface, on what OxDeAI **reuses**, **profiles**, **embeds**, or **keeps distinct** relative to the relevant IETF RATS, EAT, and COSE constructs.

COSE is not part of the RATS architecture. It is an IETF object-security standard used by EAT for its CBOR encoding, and it is in scope here for that reason rather than as a RATS component.

**What this document is:**

- A per-surface reuse/profile/embed/map-to decision record
- An explicit statement of the rationale where OxDeAI diverges
- A gate on `ExecutionReceiptV1` freeze

**What this document is not:**

- A conformance claim against any RFC
- A commitment to adopt EAT as a wire format
- A roadmap

An undocumented divergence reads as an oversight. A documented divergence reads as a design decision. The purpose of this document is to convert the former into the latter before the receipt artifact is frozen.

---

## 2. External Reference Status

Status verified against IETF Datatracker. Status line (type, stream, intended status) is recorded before any technical content, because several adjacent documents in this space have no formal standing.

| Document | Type | Stream | Status |
| --- | --- | --- | --- |
| RFC 9334 - RATS Architecture | RFC, Informational | IETF | Published, January 2023 |
| RFC 9711 - Entity Attestation Token (EAT) | RFC, Proposed Standard | IETF | Published, April 2025 |
| RFC 10013 - EAT Measured Component | RFC, Proposed Standard | IETF (was `draft-ietf-rats-eat-measured-component`, rats WG) | Published, July 2026 |
| RFC 9052 - COSE: Structures and Process | RFC, Internet Standard (STD 96) | IETF | Published, August 2022; updated by RFC 9338 |
| RFC 9053 - COSE: Initial Algorithms | RFC, Informational | IETF | Published, August 2022 |
| `draft-messous-eat-ai-01` | Internet-Draft, individual, Informational | None | Expired 2026-08-27; no formal standing |
| `draft-huang-rats-agentic-eat-cap-attest-00` | Internet-Draft, individual | None | Expired; intended status none; no formal standing |

Note on RFC 9334: it is IETF-stream and IESG-approved but **Informational**, not Standards Track. It supplies vocabulary and an architectural model, not normative wire requirements. Treat it accordingly.

Note on RFC 9052: it carries STD 96 and is the strongest-status document in this table. It is also **updated by RFC 9338**, which must be read alongside it before any adoption decision.

Note on `draft-messous` expiry: recorded from the draft's own stated expiry date of 27 August 2026. Datatracker UI state may lag; re-verify at freeze time.

Neither agentic draft is a compliance target. Both are recorded here as prior art only. `draft-huang` references EAT as RFC 9248, whereas the published EAT specification is RFC 9711. This reinforces that the draft should be treated as non-authoritative prior art only.

Subject matter note: both agentic drafts attest **the agent** — model integrity, training provenance, declared capabilities. Neither specifies an execution receipt. The overlap with `ExecutionReceiptV1` is adjacent, not equivalent.

---

## 3. Comparison Matrix

The framing is deliberately not "use EAT / don't use EAT". Each row is resolved with one of four outcomes:

- **REUSE** — adopt the external construct as-is
- **PROFILE** — adopt the construct, constrain it in an OxDeAI profile
- **EMBED** — carry the external construct inside an OxDeAI artifact
- **MAP TO** — keep the OxDeAI construct distinct, publish a concept mapping

| Question | OxDeAI | RATS / EAT / COSE | Outcome |
| --- | --- | --- | --- |
| What is attested? | authorization decision / execution evidence | entity or component state | *OPEN* |
| Who issues evidence? | authorization issuer / execution boundary | attester | *OPEN* |
| Who establishes authority? | injected `trustedKeySets`, fail-closed if absent (`verification-v1.md` §4) | verifier appraisal policy (RFC 9334) | *OPEN* |
| Role vocabulary | issuer, PEP, relying party (informal) | Attester, Verifier, Relying Party, Endorser, Reference Value Provider (named roles) | *OPEN* |
| Digest semantics | fixed SHA-256, bare lowercase hex | algorithm-explicit `[alg, val]` (RFC 10013 §4.2) | *OPEN* |
| Unknown profile | fail closed | fail closed for profiled fields (RFC 10013 §4.5) | *OPEN* |
| Independent verification | explicit protocol objective; published conformance vectors and independent Go/Python harnesses for defined subsets | core architectural assumption | *OPEN* |
| What semantic effect does the artifact have? | authorization that may permit a future execution when all verification and policy conditions hold | Evidence and Attestation Results inform a relying party's own trust decision (RFC 9334 §4.2, §8.4) | *OPEN* |
| Signature container | domain-separated Ed25519 over a canonical OxDeAI payload | `COSE_Sign1` / `COSE_Sign` structures (RFC 9052 §4) | *OPEN* |
| Wire encoding | canonical JSON, byte-exact OxDeAI serialization | CBOR/CWT with COSE, or JSON/JWT with JOSE, as profiled by EAT (RFC 9711) | *OPEN* |
| Execution authorization | core concern | not the primary abstraction | *OPEN* |

Two rows are worth stating plainly rather than leaving as symmetric differences.

**Authority establishment is symmetric, not a gap.** `trustedKeySets` is an injected verifier input and strict mode fails closed on its absence. RATS likewise places appraisal policy with the Verifier rather than in the evidence format. Neither system specifies who decides the trust anchor. This is a legitimate scope boundary on both sides.

**Role vocabulary is a real asymmetry.** RATS names its roles and gives appraisal policy an explicit architectural position. OxDeAI has the equivalent inputs without the equivalent nouns. This is a documentation gap, and it is the cheapest available bridge for interoperability positioning.

**The two COSE rows are where `ExecutionReceiptV1` most likely has a real `REUSE` / `PROFILE` / `MAP TO` decision.** Three properties of RFC 9052 are worth weighing before assuming distinctness:

- **Domain separation already exists.** The `Sig_structure` (§4.4) begins with a context string — `"Signature1"` for `COSE_Sign1` — so a signature over one structure cannot be replayed as the other. This is a structural analogy to the domain separation OxDeAI built independently, not an equivalence of canonicalization approach.
- **The signature input has explicit encoding constraints.** RFC 9052 §9 constrains the encoding of `Sig_structure`, including definite lengths and minimum-length arguments, to make the cryptographic input deterministic. This is a narrow set of restrictions aligned with the Core Deterministic Encoding Requirements of RFC 8949 §4.2.1, not a general canonicalization of the whole COSE object.
- **COSE avoids requiring a common re-encoding of protected header maps for signature verification.** The protected map is carried as serialized bytes inside a `bstr`, while the `Sig_structure` itself has defined encoding constraints. That is a structurally different answer to the problem `canonicalization-v1` addresses, and the comparison is worth making explicitly.

RFC 9052 §10 also states that a profile of the document is expected to be created per application, defining that application's interoperability requirements. `PROFILE` is therefore a first-class outcome here, not a compromise.

**Evidence vs. authorization is the row that prevents a category error.** RFC 9334 §4.2 defines Evidence as claims produced by an Attester for appraisal, and Attestation Results as the Verifier's output consumed by a Relying Party, which then applies its own appraisal policy to make application-specific decisions "such as authorization decisions" (§3). The authorization decision sits downstream of both. `AuthorizationV1` is therefore **not** EAT Evidence with different field names.

Two observations that make this row worth resolving carefully rather than assuming `MAP TO`:

- RFC 9334 §5.1 (Passport Model) describes an Attester holding an Attestation Result and presenting it to multiple Relying Parties, each applying its own policy. That is structurally close to a transferable authorization artifact. If any RATS construct maps to `AuthorizationV1`, it is Attestation Results in the Passport Model, not Evidence.
- RFC 9334 §5.1 also states that interoperability and standardization matter more for Attestation Results than for Evidence. If the mapping above holds, that is an argument in favour of taking the RATS vocabulary seriously on this row rather than declaring independence cheaply.

---

## 4. Design Notes To Open Separately

These do not block the matrix and should not wait for it.

### 4.1 Hash agility

Open a design note whose question is stated exactly as:

> Is algorithm agility worth introducing into protocol artifacts, or does a fixed algorithm provide a stronger deterministic interoperability boundary until a versioned migration is explicitly required?

The purpose is not to change `intent_hash` / `state_hash`. It is to convert implicit SHA-256 into an explicit normative decision.

One concern to evaluate is whether algorithm agility introduces additional interoperability and canonicalization surface across implementations. The countervailing benefit is explicit algorithm identification and version-independent migration. RFC 10013 §4.2 resolves this with a structured `[alg, val]` pair drawn from an IANA registry, which is not per se a per-algorithm encoding change. The design note must evaluate both directions rather than assuming either outcome.

Note that this question is **independent of the COSE rows in §3**. RFC 9052 §1 states that the omission of a digest structure from COSE is deliberate, on the grounds that each protocol wants a different set of fields in that structure. Adopting a COSE container would therefore not, by itself, force algorithm agility on OxDeAI's hash fields. The two decisions can be taken separately.

Whichever way it resolves, it must be written down before the receipt is frozen: an undocumented divergence reads as an oversight rather than a decision.

### 4.2 Provenance model (issue #197)

`packages/guard/src/provenance.ts` already carries two distinct axes:

- **How the premise was obtained:** `declared | derived | read | attested`. Only `declared` and `derived` are implemented; `read` and `attested` are documented as NOT implemented.
- **How the proposer's claim related to it:** `ClaimProvenance = "absent" | "matched" | "conflict" | "unverified"`, with `unverified` annotated in-source as explicitly not a verified value.

RFC 10013 §4.3.2 provides useful prior art for separating an authority associated with a claim or component from the signer of the enclosing evidence: it states that the authority's signature is unrelated to the attester's signature over the evidence, and that an authority identifier does not by itself indicate who signed the enclosing token. §4.5 then requires the *profile*, not the format, to define what each authority entry means.

This is an analogy, not an equivalence. OxDeAI's `attested` is not semantically identical to a measured component's `authority-id`; the useful transfer is the separation itself, not the field.

The design implication to evaluate for #197 is whether `attested`, when implemented, should carry an authority identifier distinct from the transport signer and identify the profile under which that authority's statement is interpreted.

An implementation that reduced `attested` to "someone signed this" would risk collapsing the `signed != authoritative` invariant that the module already protects at the second axis. That consideration points toward a structured object reported by the verifier rather than an enum member judged by it, but the decision belongs to #197, not to this document.

---

## 5. Exit Criteria

This document is decided when:

1. Every row in §3 carries `REUSE`, `PROFILE`, `EMBED`, or `MAP TO` with a written rationale.
2. Each divergence states what would have to change for the decision to be revisited.
3. §2 status lines are re-verified against Datatracker at the date of freeze.

Until then, `ExecutionReceiptV1` remains `Planned`. The standalone verifier over `AuthorizationV1` and `DelegationV1` does **not** wait on this document.
