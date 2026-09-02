use oxdeai_rust_verifier::types::{AuthorizationV1, KeySet};
use oxdeai_rust_verifier::verify_authorization::verify_authorization;

const AUDIENCE: &str = "pep-gateway.local";

fn load_case() -> (AuthorizationV1, KeySet) {
    let dir = env!("CARGO_MANIFEST_DIR");
    let auth: AuthorizationV1 =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/auth_case.json")).unwrap()).unwrap();
    let key_set: KeySet =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/keyset.json")).unwrap()).unwrap();
    (auth, key_set)
}

// The bundled fixture at its own deterministic protocol time: valid iff
// now < expiry, matching the current protocol contract (strict zero
// tolerance, no grace period). This must ALLOW regardless of the wall-clock
// date the test happens to run on.
#[test]
fn allow_at_last_valid_second() {
    let (auth, key_set) = load_case();
    let now = auth.expiry - 1;
    let result = verify_authorization(&auth, &key_set, AUDIENCE, now);
    assert_eq!(result.status, "ok", "expected ok, got {:?}", result.violations);
}

// Exact expiry boundary: now == expiry must deny, not allow. Pins the
// current protocol contract (expiry is exclusive) against the bundled
// fixture rather than a hand-rolled one.
#[test]
fn deny_at_expiry_boundary() {
    let (auth, key_set) = load_case();
    let now = auth.expiry;
    let result = verify_authorization(&auth, &key_set, AUDIENCE, now);
    assert_eq!(result.status, "invalid");
    assert_eq!(result.violations[0].code, "AUTH_EXPIRED");
}

// A fixture whose expiry has actually passed must fail closed. This is the
// regression for the original defect: relying on real "now" without an
// override silently turns the canonical ALLOW case into AUTH_EXPIRED once
// the fixture's expiry is in the past.
#[test]
fn deny_when_expired() {
    let (auth, key_set) = load_case();
    let now = auth.expiry + 10_000_000; // far past expiry, real-clock-independent
    let result = verify_authorization(&auth, &key_set, AUDIENCE, now);
    assert_eq!(result.status, "invalid");
    assert_eq!(result.violations[0].code, "AUTH_EXPIRED");
}

// Tampering any signed field must invalidate the signature. Mutating
// intent_hash after signing (rather than corrupting the signature bytes
// directly) proves the signature actually binds the payload, not just that
// malformed base64 is rejected.
#[test]
fn deny_on_tampered_field() {
    let (mut auth, key_set) = load_case();
    let now = auth.expiry - 1;
    auth.intent_hash = "0".repeat(64);
    let result = verify_authorization(&auth, &key_set, AUDIENCE, now);
    assert_eq!(result.status, "invalid");
    assert_eq!(result.violations[0].code, "AUTH_SIGNATURE_INVALID");
}
