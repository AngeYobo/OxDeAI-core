# OxDeAI Canonicalization Specification v1

## 1. Purpose

This specification defines a deterministic canonicalization procedure for structured authorization inputs.

The canonicalization function transforms an input value into a unique UTF-8 encoded JSON byte sequence suitable for hashing, signing, replay protection, and cross-language verification.

The canonicalization procedure MUST guarantee:

- deterministic serialization
- byte-stability
- cross-language equality
- fail-closed rejection of unsupported inputs

---

## 2. Canonicalization Function

The canonicalization function is defined as:

```text
C(input) -> canonical_bytes
```

Where:

- `input` is a structured value conforming to this specification
- `canonical_bytes` is the canonical UTF-8 encoded JSON representation

---

## 3. Equivalence

Two inputs are considered equivalent if:

```text
C(x) == C(y)
```

No semantic equivalence beyond byte equality is assumed.

---

## 4. Output Format

The canonical output MUST be:

- valid JSON (RFC 8259)
- encoded as UTF-8
- emitted without BOM
- minified (no insignificant whitespace)
- serialized deterministically

---

## 5. Input Parsing Requirements

Inputs MUST be parsed deterministically before canonicalization.

- duplicate keys MUST be detected during parsing
- inputs that cannot be deterministically parsed MUST be rejected

Invalid UTF-8 sequences MUST cause canonicalization failure.

---

## 6. Serialization Rules (normative)

Implementations MUST apply the following rules, in order, to produce the canonical JSON bytes:

- Strings: normalize to Unicode NFC and encode as JSON strings.
- Object keys: NFC-normalize, reject duplicates after normalization, then sort keys by byte-wise UTF-8 order.
- Arrays: preserve element order.
- Numbers: only integers in the safe IEEE-754 range **[-9007199254740991, 9007199254740991]** are allowed as JSON numbers. Floating-point values and `NaN`/`±Inf` MUST be rejected.
- BigInt values, when present in a runtime representation, MUST be serialized as JSON strings.
- Timestamps: if the object key is exactly `"ts"`, the value MUST be an integer within the safe range; otherwise canonicalization MUST fail.
- Unsupported runtime types, including functions, symbols, and `undefined`, MUST be rejected.
- Output MUST be minified and UTF-8 encoded without BOM.

---

## 7. Error Codes (normative)

When rejecting inputs, implementations MUST fail closed and SHOULD use the following canonical error codes to enable cross-language parity:

- `FLOAT_NOT_ALLOWED`
- `UNSAFE_INTEGER_NUMBER`
- `DUPLICATE_KEY`
- `INVALID_TIMESTAMP`
- `UNSUPPORTED_TYPE`
- `KEY_RESOLUTION_FAILED` (if post-normalization lookup cannot resolve)

Additional runtime-specific errors MUST NOT leak implementation details and MUST result in canonicalization failure.

### 7.1 Common invalid cases and canonical error codes

| Invalid input | Canonical error code |
|---|---|
| Any floating-point value / NaN / ±Inf | `FLOAT_NOT_ALLOWED` |
| Integer outside the safe range when represented as a JSON number | `UNSAFE_INTEGER_NUMBER` |
| Duplicate key after NFC normalization | `DUPLICATE_KEY` |
| Key `ts` with a non-integer or unsafe value | `INVALID_TIMESTAMP` |
| Unsupported runtime type (function, symbol, etc.) | `UNSUPPORTED_TYPE` |

The error codes above are SHOULD-level interoperability recommendations. The requirement to reject the corresponding invalid inputs is MUST-level.

---

## 8. Allowed Types

The canonical data model permits the following JSON-compatible types:

- object
- array
- string
- integer within the safe range when represented as a JSON number
- boolean
- null

Runtime BigInt values are not a canonical JSON type. When accepted by an implementation, they MUST be converted to their JSON string representation according to §6.

---

## 9. Forbidden Types

The following MUST cause canonicalization failure when presented directly as runtime values:

- floating-point numbers
- NaN
- Infinity
- undefined
- functions
- symbols
- binary values
- Map / Set
- Date objects
- custom class instances
- language-specific objects not otherwise defined by this specification

---

## 10. Integer Rules

Integers MAY be represented as JSON numbers only if they are within:

```text
[-(2^53 - 1), +(2^53 - 1)]
```

i.e.:

```text
[-9007199254740991, 9007199254740991]
```

Integers outside that range MUST be represented as decimal JSON strings rather than JSON numbers.

### Allowed

Safe integer represented as a JSON number:

```json
{"count":42}
```

Integer outside the safe numeric range represented as a string:

```json
{"count":"9007199254740993"}
```

### Not Allowed

Unsafe integer represented as a JSON number:

```json
{"count":9007199254740993}
```

Floating-point value:

```json
{"count":42.5}
```

Both inputs above MUST cause canonicalization failure according to the rules defined in this specification.