# OxDeAI and the EU AI Act: Record-Keeping Mapping

**Document type:** Compliance positioning artifact
**Status:** Working draft — not reviewed by counsel
**Scope:** Record-keeping and log integrity only (Articles 12, 19, 26(6)). No other obligation is mapped.

**Provenance**

| Item | Value |
|---|---|
| OxDeAI revision | `620b84f` |
| Technical scope reviewed | `packages/core/src/audit/`, `packages/core/src/verification/`, `packages/core/src/types/authorization.ts` |
| Legal baseline | Regulation (EU) 2024/1689 |
| Article text consulted | European Commission AI Act Service Desk (`ai-act-service-desk.ec.europa.eu`), 2026-09-05. That tool publishes the official version of 13 June 2024. |
| Consolidated version not read | `02024R1689-20260727`, in force from 2026-07-27, has not been read directly. Differences from the 13 June 2024 text have not been assessed. |
| Pending amendment | The Service Desk displays a Digital Omnibus on AI amendment notice on some provisions, stating that its text does not yet reflect those amendments. Checked 2026-09-05: present on Article 3, relied on in §2; absent on Articles 19 and 26. Article 12 not checked directly. Absence of the notice on a Service Desk page is not a legal analysis of the consolidated text. |
| Not yet done | Direct reading of the consolidated EUR-Lex text; assessment of Digital Omnibus amendments; review by qualified counsel |

**Related documents:** `docs/standardization/aarm-alignment.md`, `docs/architecture/decision-is-not-execution.md`, `docs/spec/verification/verification-v1.md`, `SECURITY.md`

---

## 1. Purpose and Scope

Regulation (EU) 2024/1689 places record-keeping obligations on providers and deployers of
high-risk AI systems. This document identifies which technical artifacts OxDeAI produces that
may support evidence toward a subset of those obligations, and states explicitly what those
artifacts do not establish.

**What this document is:**

- A mapping between OxDeAI's audit event structure and three specific articles
- An explicit statement of properties OxDeAI does not provide
- A statement of what remains a deployment responsibility

**What this document is not:**

- A claim that OxDeAI is compliant with the AI Act
- A claim that deploying OxDeAI makes any system compliant
- A determination of regulatory status for any party
- Legal advice, or a substitute for it

## 2. Regulatory Status

OxDeAI is an authorization and enforcement software component. This document does not
determine whether OxDeAI, an OxDeAI-based product, or any system incorporating OxDeAI
qualifies as an AI system, a high-risk AI system, a safety component, or any other regulated
product under Regulation (EU) 2024/1689.

Provider, deployer, and other operator status attaches to natural or legal persons, public
authorities, agencies, or other bodies as defined by the Regulation (Art. 3(3), Art. 3(4)),
and depends on the facts of a particular case, including intended purpose, integration,
placing on the market, and putting into service. Nothing here assigns or disclaims regulatory
status for Oxalio Labs or for any integrator.

The Regulation also defines 'safety component' (Art. 3(14)) by reference to the function a
component fulfils and the consequences of its failure. Whether that definition reaches an
authorization component in any given product is a question of fact, and is not determined
here.

The mapping below is limited to identifying technical artifacts that may support evidence for
specific record-keeping obligations.

## 3. Article 12 — Record-Keeping

Article 12(1) requires that high-risk AI systems technically allow for the automatic recording
of events over the lifetime of the system. Article 12(2) requires logging capabilities
appropriate to traceability, covering three identified purposes: situations that may present a
risk or involve a substantial modification, post-market monitoring, and operational monitoring
by deployers.

### 3.1 What OxDeAI emits

`packages/core/src/audit/AuditLog.ts` defines five event types, each carrying a `timestamp`
and an optional `policyId`:

| Event | Fields |
|---|---|
| `INTENT_RECEIVED` | `intent_hash`, `agent_id` |
| `DECISION` | `intent_hash`, `decision` (`ALLOW` \| `DENY`), `reasons[]`, `policy_version` |
| `AUTH_EMITTED` | `authorization_id`, `intent_hash`, `expires_at` |
| `STATE_CHECKPOINT` | `stateHash` |
| `EXECUTION_ATTESTED` | `intent_hash`, `execution_ref` — **declared but never emitted, see §3.4** |

Emission is automatic and occurs as part of the authorization process rather than through
operator action.

Where OxDeAI is integrated into a high-risk AI system, these events may contribute evidence
toward the automatic-recording capability required by Article 12(1), for the authorization
decision surface only. They do not establish Article 12(1) compliance for the surrounding AI
system or for its full lifecycle.

`DECISION` events carry structured `reasons[]` and a `policy_version`. These may support
traceability of authorization decisions where such decisions are relevant to the risk,
post-market monitoring, or operational-monitoring purposes identified in Article 12(2).
OxDeAI does not determine whether a particular logged event is legally sufficient or relevant
for those purposes; a `DENY` is not automatically a risk-relevant event within the meaning of
the Regulation.

### 3.2 Tamper evidence

Article 12 does not prescribe a specific log-integrity mechanism. OxDeAI additionally
provides a hash-chain mechanism for detecting modifications to a retained event sequence,
subject to the limitations below.

`packages/core/src/audit/HashChainedLog.ts` chains each event to its predecessor as
`SHA-256(prev_hash || "\n" || canonicalJson(event))`, anchored at a fixed genesis hash. The
head hash is a pointer over the entire sequence. `verifyAuditEvents` in
`packages/core/src/verification/` recomputes the chain independently.

**What this provides.** An alteration or removal within a retained sequence changes the
recomputed head hash. A third party that possesses an independently trusted reference head
and the candidate event sequence can therefore detect such a modification.

**What this does not provide.** Tamper evidence for a retained sequence is conditional on the
reference head being held independently of the party that produced the log. It does not by
itself establish:

- completeness of event capture — that every event that should have been emitted was emitted
- authenticity or custody of the reference head itself
- who stored the log, or who held it between emission and inspection
- persistence or retention over any period
- trusted timestamping of the recorded events
- that an authorized action was executed

A party controlling the entire log with no independently anchored reference head can recompute
a self-consistent chain. Chain of custody is a property of a deployment's handling procedures,
not of this artifact.

### 3.3 Coverage limits

Only authorization events are recorded. Model inference, data ingestion, output delivery, and
every other part of an AI system's operation are outside this log.

### 3.4 `EXECUTION_ATTESTED` is declared but not emitted

The type exists in `AuditLog.ts:28`. No code path produces it. The log therefore evidences
that a decision was made, not that the corresponding action was executed.

**No `ALLOW` decision, `AUTH_EMITTED` event, or authorization artifact should be interpreted
as proof of execution.** See `docs/architecture/decision-is-not-execution.md`.

## 4. Articles 19 and 26(6) — Log Retention

Article 19 requires providers to keep automatically generated logs for a period appropriate to
the intended purpose, of at least six months, to the extent such logs are under their control
and unless applicable Union or national law provides otherwise. Article 26(6) places an
equivalent obligation on deployers.

OxDeAI does not implement log persistence or regulatory retention. `HashChainedLog` is an
in-memory mechanism (`private chain: ChainedEntry[]`). It provides no durable storage backend,
no retention scheduler, no access-control regime, no archival policy, and no deletion policy.

Where OxDeAI-generated events are used as part of Article 12 logging, satisfying the retention
requirements of Articles 19 and 26(6) — including the applicable retention period and the
treatment of those records under data-protection or other applicable law — remains a
deployment responsibility.

Both articles carry a parallel provision for regulated financial institutions. Article 19(2)
requires providers that are financial institutions subject to internal-governance requirements
under Union financial services law to maintain these logs as part of the documentation kept
under the relevant financial services law. The second subparagraph of Article 26(6) states the
corresponding rule for deployers that are financial institutions.

For such institutions, logging evidence may therefore need to fit into an existing sectoral
governance and documentation regime rather than being managed as a standalone AI Act record
set. OxDeAI does not implement that integration.

OxDeAI contributes the events and the hash-chain verification mechanism described in §3.2,
with the limits stated there. It does not provide persistence or regulatory retention.

## 5. Obligations Not Mapped

The following obligations are outside the scope of this mapping. No compliance claim, and no
claim of non-relevance, is made for them in this document.

| Article | Obligation | Status in this document |
|---|---|---|
| Art. 9 | Risk management system | No mapping claimed |
| Art. 10 | Data and data governance | No mapping claimed |
| Art. 11 | Technical documentation (Annex IV) | No mapping claimed |
| Art. 13 | Transparency and instructions for use | No mapping claimed |
| Art. 14 | Human oversight | No mapping claimed — see §5.1 |
| Art. 15 | Accuracy, robustness and cybersecurity | Deliberately not mapped — see §5.2 |
| Art. 18 | Provider documentation retention | No mapping claimed |
| Art. 27 | Fundamental rights impact assessment | No mapping claimed |
| Art. 49 | Registration in the EU database | No mapping claimed |

### 5.1 Article 14 — Human oversight

Article 14 requires that high-risk AI systems be designed so that natural persons can
effectively oversee them, including the ability to intervene or interrupt operation. It does
not require any particular decision primitive.

OxDeAI does not currently implement a native human-oversight workflow, nor a `STEP_UP` or
`HUMAN_APPROVAL` decision primitive. Its core authorization decision is binary:
`"ALLOW" | "DENY"` (`packages/core/src/types/authorization.ts:11`). Any human-review workflow,
approval authority, interface, or other oversight mechanism required by a deployment must
therefore be supplied outside the current OxDeAI core.

This document makes no claim that OxDeAI satisfies Article 14. It does not exclude that a
deployment may use OxDeAI to enforce an approval state established elsewhere.

### 5.2 Article 15 — Why it is deliberately not mapped

Article 15 addresses accuracy, robustness, and cybersecurity, including resilience against
attempts by unauthorised third parties to alter the use, outputs, or performance of a
high-risk AI system.

Several OxDeAI properties — fail-closed authorization, replay protection, and cryptographic
binding of a decision to an action and to state — are plausibly relevant to technical controls
under this article. Mapping them would require a security argument of a different kind from
the record-keeping argument made here, and would need to account for the residual risks
recorded in `SECURITY.md`. That mapping is deliberately deferred rather than assumed absent.

## 6. Summary

| Capability | Status |
|---|---|
| Automatic emission of authorization decision events | Provided as a technical capability, for the authorization surface only |
| Structured decision records with reasons and policy version | Provided as an OxDeAI artifact property; regulatory sufficiency not established |
| Audit-sequence tamper evidence | Provided at artifact level, conditional on an independently retained trusted reference head |
| Chain of custody | Not provided |
| Completeness of event capture | Not provided |
| Trusted timestamping | Not provided |
| Evidence of execution | Not provided |
| Log persistence and retention | Not provided |
| Article 12(1) compliance for a surrounding AI system | Not established |
| All other obligations | Not mapped |

## 7. Cross-References

| Document | Relation |
|---|---|
| `docs/standardization/aarm-alignment.md` | Positioning against the AARM specification — a voluntary standard, not a legal obligation, and a distinct register from this document. Itself a working draft. |
| `docs/architecture/decision-is-not-execution.md` | Why an authorization decision is not evidence of execution |
| `docs/spec/verification/verification-v1.md` | Snapshot hash and audit chain integrity validation |
| `docs/spec/state-provider-requirements.md` | State provider integrity; deployment compliance boundary |
| `SECURITY.md` | Residual risks, including RT-TRUST-1 |

---

*This document makes no conformity claim under Regulation (EU) 2024/1689. Determining whether
a given deployment satisfies any obligation of that Regulation is the responsibility of the
provider or deployer of the AI system concerned, in consultation with qualified counsel.*
